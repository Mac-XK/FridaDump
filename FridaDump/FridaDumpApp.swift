//
//  FridaDumpApp.swift
//  FridaDump
//
//  Created by MacXK on 2026/11/4.
//

import SwiftUI

@main
struct FridaDumpApp: App {
    init() {
        HeadlessRunner.runIfRequested()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
