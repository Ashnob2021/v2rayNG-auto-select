package com.v2ray.ang.ui.main

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class MainImportMenuTest {

    @Test
    fun regularShareMenuContainsOnlyShareActions() {
        val expected = listOf(
            ServerMenuAction.ShareQRCode,
            ServerMenuAction.ShareClipboard,
            ServerMenuAction.ShareFullContent,
        )
        assertEquals(expected, serverMenuActions(isComplexProfile = false, includeManagementActions = false))
    }

    @Test
    fun regularMoreMenuContainsEveryActionInDisplayOrder() {
        assertEquals(
            ServerMenuAction.entries,
            serverMenuActions(isComplexProfile = false, includeManagementActions = true, canDiagnoseDns = true),
        )
    }

    @Test
    fun moreMenuWithoutDomainExcludesDiagnoseDns() {
        assertEquals(
            ServerMenuAction.entries - ServerMenuAction.DiagnoseDns,
            serverMenuActions(isComplexProfile = false, includeManagementActions = true),
        )
    }

    @Test
    fun complexMoreMenuExcludesDiagnoseDns() {
        assertEquals(
            listOf(ServerMenuAction.ShareFullContent, ServerMenuAction.Edit, ServerMenuAction.Delete),
            serverMenuActions(isComplexProfile = true, includeManagementActions = true, canDiagnoseDns = true),
        )
    }

    @Test
    fun shareMenuNeverContainsDiagnoseDns() {
        assertEquals(
            listOf(
                ServerMenuAction.ShareQRCode,
                ServerMenuAction.ShareClipboard,
                ServerMenuAction.ShareFullContent,
            ),
            serverMenuActions(isComplexProfile = false, includeManagementActions = false, canDiagnoseDns = true),
        )
    }

    @Test
    fun complexShareMenuContainsOnlyFullContent() {
        assertEquals(
            listOf(ServerMenuAction.ShareFullContent),
            serverMenuActions(isComplexProfile = true, includeManagementActions = false),
        )
    }

    @Test
    fun complexMoreMenuRetainsManagementActions() {
        val expected = listOf(
            ServerMenuAction.ShareFullContent,
            ServerMenuAction.Edit,
            ServerMenuAction.Delete,
        )
        assertEquals(expected, serverMenuActions(isComplexProfile = true, includeManagementActions = true))
    }
}
