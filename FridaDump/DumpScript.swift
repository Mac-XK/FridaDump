import Foundation

/// 注入到目标进程的 frida 脚本。
/// 职责：解密 Mach-O 段 -> 遍历 .app 目录 -> 分块回传给宿主。
enum DumpScript {
    static let source = #"""
    // ============ 基础工具 ============
    var _keepAlive = [];
    function allocStr(s) {
        var p = Memory.allocUtf8String(s);
        _keepAlive.push(p);
        if (_keepAlive.length > 300) _keepAlive.shift();
        return p;
    }

    function findExport(name) {
        var mods = Process.enumerateModules();
        for (var i = 0; i < mods.length; i++) {
            var a = mods[i].findExportByName(name);
            if (a) return a;
        }
        return null;
    }

    function log(m) { send({ t: 'log', m: String(m) }); }

    var O_RDONLY = 0, O_RDWR = 2, O_CREAT = 512;
    var SEEK_SET = 0, SEEK_CUR = 1, SEEK_END = 2;

    function getExportFunction(name, ret, args) {
        var nptr = findExport(name);
        if (nptr === null) { log('cannot find ' + name); return null; }
        return new NativeFunction(nptr, ret, args);
    }

    var wrapper_open = getExportFunction('open', 'int', ['pointer', 'int', 'int']);
    var read = getExportFunction('read', 'int', ['int', 'pointer', 'int']);
    var write = getExportFunction('write', 'int', ['int', 'pointer', 'int']);
    var lseek = getExportFunction('lseek', 'int64', ['int', 'int64', 'int']);
    var close = getExportFunction('close', 'int', ['int']);
    var remove = getExportFunction('remove', 'int', ['pointer']);
    var access = getExportFunction('access', 'int', ['pointer', 'int']);
    var dlopen = getExportFunction('dlopen', 'pointer', ['pointer', 'int']);
    var chmodFn = getExportFunction('chmod', 'int', ['pointer', 'int']);
    var mallocFn = new NativeFunction(findExport('malloc'), 'pointer', ['size_t']);
    var freeFn = new NativeFunction(findExport('free'), 'void', ['pointer']);

    function openFd(pathname, flags, mode) {
        return wrapper_open(allocStr(pathname), flags, mode);
    }

    function getU8(p) { return p.readU8(); }
    function getU32(p) { return p.readU32(); }
    function putU64(p, n) { return p.writeU64(n); }

    function getDocumentDir() {
        var getenvFn = new NativeFunction(findExport('getenv'), 'pointer', ['pointer']);
        var home = getenvFn(allocStr('HOME')).readUtf8String();
        return home + '/Documents';
    }

    // ============ 模块枚举 ============
    var modules = null;

    function getAllAppModules() {
        var out = [];
        var tmp = Process.enumerateModules();
        for (var i = 0; i < tmp.length; i++) {
            if (tmp[i].path.indexOf('.app') !== -1) out.push(tmp[i]);
        }
        modules = out;
        return out;
    }

    var FAT_CIGAM = 0xbebafeca, FAT_MAGIC = 0xcafebabe;
    var MH_MAGIC = 0xfeedface, MH_CIGAM = 0xcefaedfe;
    var MH_MAGIC_64 = 0xfeedfacf, MH_CIGAM_64 = 0xcffaedfe;
    var LC_ENCRYPTION_INFO = 0x21, LC_ENCRYPTION_INFO_64 = 0x2C;

    function pad(s, n) { return Array(n - s.length + 1).join('0') + s; }

    function swap32(value) {
        value = pad(value.toString(16), 8);
        var r = '';
        for (var i = 0; i < value.length; i += 2) {
            r += value.charAt(value.length - i - 2);
            r += value.charAt(value.length - i - 1);
        }
        return parseInt(r, 16);
    }

    // ============ 解密单个 Mach-O ============
    var BUFSIZE = 256 * 1024;    // 256KB/块，兼顾速度与内存
    function dumpModule(name) {
        var all = getAllAppModules();
        var target = null;
        for (var i = 0; i < all.length; i++) {
            if (all[i].path.indexOf(name) !== -1) { target = all[i]; break; }
        }
        if (target === null) { log('module not found: ' + name); return null; }

        var modbase = target.base;
        var newmodname = target.name;
        var newmodpath = getDocumentDir() + '/' + newmodname + '.fid';
        var oldmodpath = target.path;

        if (!access(allocStr(newmodpath), 0)) remove(allocStr(newmodpath));

        var fmodule = openFd(newmodpath, O_CREAT | O_RDWR, 384); // 0600
        var foldmodule = openFd(oldmodpath, O_RDONLY, 0);
        if (fmodule === -1 || foldmodule === -1) { log('open failed: ' + newmodpath); return null; }
        chmodFn(allocStr(newmodpath), 384); // 保证后续可读回

        var is64 = false, hdrSize = 0;
        var magic = getU32(modbase);
        var cpuType = getU32(modbase.add(4));
        var cpuSubtype = getU32(modbase.add(8));
        if (magic === MH_MAGIC || magic === MH_CIGAM) { is64 = false; hdrSize = 28; }
        else if (magic === MH_MAGIC_64 || magic === MH_CIGAM_64) { is64 = true; hdrSize = 32; }

        var buffer = mallocFn(BUFSIZE);
        read(foldmodule, buffer, BUFSIZE);

        magic = getU32(buffer);
        if (magic === FAT_CIGAM || magic === FAT_MAGIC) {
            var off = 4;
            var archs = swap32(getU32(buffer.add(off)));
            var fileoffset = 0, filesize = 0;
            for (var i = 0; i < archs; i++) {
                var ct = swap32(getU32(buffer.add(off + 4)));
                var cst = swap32(getU32(buffer.add(off + 8)));
                if (cpuType === ct && cpuSubtype === cst) {
                    fileoffset = swap32(getU32(buffer.add(off + 12)));
                    filesize = swap32(getU32(buffer.add(off + 16)));
                    break;
                }
                off += 20;
            }
            if (fileoffset === 0 || filesize === 0) { close(fmodule); close(foldmodule); return null; }

            lseek(fmodule, 0, SEEK_SET);
            lseek(foldmodule, fileoffset, SEEK_SET);
            var n = parseInt(filesize / BUFSIZE);
            for (var i = 0; i < n; i++) { read(foldmodule, buffer, BUFSIZE); write(fmodule, buffer, BUFSIZE); }
            if (filesize % BUFSIZE) {
                read(foldmodule, buffer, filesize % BUFSIZE);
                write(fmodule, buffer, filesize % BUFSIZE);
            }
        } else {
            var got = 0;
            lseek(foldmodule, 0, SEEK_SET);
            lseek(fmodule, 0, SEEK_SET);
            while ((got = read(foldmodule, buffer, BUFSIZE)) > 0) {
                write(fmodule, buffer, got);
            }
        }

        var ncmds = getU32(modbase.add(16));
        var off2 = hdrSize;
        var offsetCryptid = -1, cryptOff = 0, cryptSize = 0;
        for (var i = 0; i < ncmds; i++) {
            var cmd = getU32(modbase.add(off2));
            var cmdsize = getU32(modbase.add(off2 + 4));
            if (cmd === LC_ENCRYPTION_INFO || cmd === LC_ENCRYPTION_INFO_64) {
                offsetCryptid = off2 + 16;
                cryptOff = getU32(modbase.add(off2 + 8));
                cryptSize = getU32(modbase.add(off2 + 12));
            }
            off2 += cmdsize;
        }

        if (offsetCryptid !== -1) {
            var tpbuf = Memory.alloc(8);
            putU64(tpbuf, 0);
            lseek(fmodule, offsetCryptid, SEEK_SET);
            write(fmodule, tpbuf, 4);
            lseek(fmodule, cryptOff, SEEK_SET);
            write(fmodule, modbase.add(cryptOff), cryptSize);
        }

        close(fmodule);
        close(foldmodule);
        return newmodpath;
    }

    // ============ 目录遍历（readdir，按 d_namlen 限长） ============
    var DT_DIR = 4;

    var opendirFn = new NativeFunction(findExport('opendir'), 'pointer', ['pointer']);
    var readdirFn = new NativeFunction(findExport('readdir'), 'pointer', ['pointer']);
    var closedirFn = new NativeFunction(findExport('closedir'), 'int', ['pointer']);

    function listDir(path) {
        var out = [];
        var dir = opendirFn(allocStr(path));
        if (dir.isNull()) return out;

        var ent;
        while (!(ent = readdirFn(dir)).isNull()) {
            var namlen = ent.add(18).readU16();
            if (namlen === 0 || namlen > 255) continue;
            var name = ent.add(21).readUtf8String(namlen);
            if (name === '.' || name === '..') continue;
            out.push({ name: name, type: ent.add(20).readU8() });
        }
        closedirFn(dir);
        return out;
    }

    function walk(root, rel, out) {
        var queue = [{ full: root, rel: rel }];
        while (queue.length > 0) {
            var cur = queue.pop();
            var entries = listDir(cur.full);
            for (var i = 0; i < entries.length; i++) {
                var e = entries[i];
                var full = cur.full + '/' + e.name;
                var r = cur.rel + '/' + e.name;
                if (e.type === DT_DIR) queue.push({ full: full, rel: r });
                else out.push({ full: full, rel: r });
            }
        }
    }

    // ============ 文件回传 ============
    var CHUNK = 1024 * 512;

    function sendFile(fullPath, relPath) {
        var fd = openFd(fullPath, O_RDONLY, 0);
        if (fd < 0) { send({ t: 'skip', p: relPath, e: 'open=' + fd }); return; }

        var size = Number(lseek(fd, 0, SEEK_END));
        lseek(fd, 0, SEEK_SET);
        send({ t: 'begin', p: relPath, s: size });

        var buf = mallocFn(BUFSIZE);
        var got = 0, total = 0, blocks = 0;
        while ((got = read(fd, buf, BUFSIZE)) > 0) {
            var chunk = buf.readByteArray(got);
            send({ t: 'chunk' }, chunk);
            total += got;
            blocks++;
            if (blocks % 8 === 0) Thread.sleep(0.003);   // 节流，防止发送队列积压撑爆内存
        }
        close(fd);
        freeFn(buf);
        send({ t: 'end', p: relPath, s: total });
    }

    // ============ 主流程 ============
    function runDump() {
        var mods = getAllAppModules();

        var appPath = '';
        for (var i = 0; i < mods.length; i++) {
            var idx = mods[i].path.indexOf('.app/');
            if (idx !== -1) { appPath = mods[i].path.substring(0, idx + 4); break; }
        }
        if (appPath === '') { send({ t: 'error', m: '找不到 .app 路径' }); return; }

        var appName = appPath.substring(appPath.lastIndexOf('/') + 1);
        var rootDir = appPath.substring(0, appPath.lastIndexOf('/') + 1);
        send({ t: 'app', name: appName, path: appPath });

        log('加载未启动的 framework...');
        loadAllDynamicLibrary(appPath);

        mods = getAllAppModules();
        var dumped = {};
        var order = [];

        for (var i = 0; i < mods.length; i++) {
            var p = mods[i].path;
            var rel = p.substring(rootDir.length);
            send({ t: 'module', p: rel });
            var fid = null;
            for (var attempt = 0; attempt < 3 && fid === null; attempt++) {
                try {
                    fid = dumpModule(p);
                } catch (e) {
                    log('模块重试 ' + (attempt + 1) + ': ' + e);
                }
            }
            if (fid !== null) { dumped[rel] = fid; order.push(rel); }
        }

        log('遍历资源文件...');
        var files = [];
        walk(appPath, appName, files);
        var sentCount = 0;
        for (var i = 0; i < files.length; i++) {
            if (dumped[files[i].rel] !== undefined) continue;
            sendFile(files[i].full, files[i].rel);
            sentCount++;
        }
        log('资源文件 ' + sentCount + ' 个');

        log('回传解密后的二进制...');
        for (var i = 0; i < order.length; i++) {
            sendFile(dumped[order[i]], order[i]);
        }

        send({ t: 'done' });
    }

    function loadAllDynamicLibrary(appPath) {
        var mods = Process.enumerateModules();
        var loaded = {};
        for (var i = 0; i < mods.length; i++) loaded[mods[i].name] = true;

        var entries = listDir(appPath);
        for (var i = 0; i < entries.length; i++) {
            var e = entries[i];
            if (e.name.slice(-10) === '.framework') {
                var base = e.name.slice(0, -10);
                if (!loaded[base] && dlopen(allocStr(appPath + '/' + e.name + '/' + base), 9)) {
                    log('load ' + e.name);
                }
            }
        }

        var dylds = listDir(appPath + '/Frameworks');
        for (var i = 0; i < dylds.length; i++) {
            var n = dylds[i].name;
            if (n.slice(-6) === '.dylib' && !loaded[n] && dlopen(allocStr(appPath + '/Frameworks/' + n), 9)) {
                log('dlopen ' + n);
            }
        }
    }

    // ============ 消息入口 ============
    function handleCommand(message, data) {
        if (message && message.cmd === 'dump') {
            try { runDump(); } catch (e) { send({ t: 'error', m: String(e) + ' @ ' + (e.stack || '') }); }
        }
    }

    send({ t: 'log', m: 'script ready ' + Process.arch });
    recv(handleCommand);
    """#
}
