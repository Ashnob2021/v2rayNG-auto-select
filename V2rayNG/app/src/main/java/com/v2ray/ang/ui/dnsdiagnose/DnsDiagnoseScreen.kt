package com.v2ray.ang.ui.dnsdiagnose

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.v2ray.ang.R
import com.v2ray.ang.ui.compose.AppTopBar
import com.v2ray.ang.ui.compose.ItemDivider

@Composable
fun DnsDiagnoseScreen(
    state: DnsDiagnoseUiState,
    onBackClick: () -> Unit,
    onAction: (DnsDiagnoseAction) -> Unit,
) {
    Scaffold(
        contentWindowInsets = WindowInsets(0),
        topBar = {
            AppTopBar(
                title = stringResource(R.string.dns_diagnose_title),
                onBackClick = onBackClick,
                isLoading = state.probing,
            )
        },
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState())
        ) {
            when (state.phase) {
                DnsDiagnosePhase.LOADING -> {
                    Spacer(modifier = Modifier.height(32.dp))
                    CircularProgressIndicator()
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(text = stringResource(R.string.dns_diagnose_testing))
                }

                DnsDiagnosePhase.NO_PROFILE -> {
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(text = stringResource(R.string.dns_diagnose_no_profile))
                }

                DnsDiagnosePhase.NO_DOMAIN -> {
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(text = stringResource(R.string.dns_diagnose_no_domain))
                }

                DnsDiagnosePhase.READY -> {
                    DnsDiagnoseContent(state = state, onAction = onAction)
                }
            }
        }
    }
}

@Composable
private fun DnsDiagnoseContent(
    state: DnsDiagnoseUiState,
    onAction: (DnsDiagnoseAction) -> Unit,
) {
    Spacer(modifier = Modifier.height(8.dp))

    // Domain: read from the selected config, never typed by hand.
    Text(
        text = stringResource(R.string.dns_diagnose_domain_label),
        style = MaterialTheme.typography.titleMedium,
        fontWeight = FontWeight.Bold,
    )
    if (state.remarks.isNotEmpty()) {
        Text(text = state.remarks, style = MaterialTheme.typography.bodyMedium)
    }
    Text(text = state.domain, style = MaterialTheme.typography.bodyLarge)
    Text(
        text = stringResource(R.string.dns_diagnose_domain_note),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )

    // Applied fix: always visible while the flag is on, before or after
    // the test and whatever the verdict says. Before this, the applied
    // state and the Revert button only existed inside the Fix section,
    // which is shown only when the verdict is a DNS problem — so on a
    // network where DNS looks healthy the flag was invisible and there
    // was no way to revert it from this screen, even though the fix
    // itself can break the config on that network.
    if (state.flagOn) {
        Spacer(modifier = Modifier.height(16.dp))
        ItemDivider()
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = stringResource(R.string.dns_diagnose_fix_title),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
        )
        Text(
            text = stringResource(R.string.dns_diagnose_applied),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.primary,
        )
        Spacer(modifier = Modifier.height(8.dp))
        OutlinedButton(
            onClick = { onAction(DnsDiagnoseAction.RevertFix) },
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(text = stringResource(R.string.dns_diagnose_revert))
        }
        Text(
            text = stringResource(R.string.dns_diagnose_revert_note),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = stringResource(R.string.dns_diagnose_restart_note),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (state.fixVerified) {
            Text(
                text = stringResource(R.string.dns_diagnose_fix_verified),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.primary,
            )
        }
    }

    Spacer(modifier = Modifier.height(16.dp))
    ItemDivider()
    Spacer(modifier = Modifier.height(16.dp))

    // Probe rows.
    Text(
        text = stringResource(R.string.dns_diagnose_tests_title),
        style = MaterialTheme.typography.titleMedium,
        fontWeight = FontWeight.Bold,
    )
    Text(
        text = stringResource(R.string.dns_diagnose_tests_note),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Spacer(modifier = Modifier.height(8.dp))
    state.rows.forEach { row ->
        ProbeRow(result = row)
    }
    if (state.probing) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            CircularProgressIndicator()
            Text(
                text = stringResource(R.string.dns_diagnose_testing),
                modifier = Modifier.padding(start = 12.dp),
            )
        }
    }

    // Verdict.
    state.verdict?.let { verdict ->
        Spacer(modifier = Modifier.height(16.dp))
        ItemDivider()
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = stringResource(R.string.dns_diagnose_verdict_title),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
        )
        Text(text = verdictText(verdict), style = MaterialTheme.typography.bodyLarge)
        if (verdict.kind == DnsVerdictKind.HIJACKED || verdict.kind == DnsVerdictKind.FILTERED) {
            if (verdict.dohIps.isNotEmpty()) {
                Text(
                    text = stringResource(
                        R.string.dns_diagnose_verdict_hijacked_evidence,
                        verdict.systemIps.joinToString(", "),
                        verdict.dohIps.joinToString(", "),
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                )
            } else if (verdict.kind == DnsVerdictKind.FILTERED) {
                // The sinkhole address alone proves filtering, but no DoH
                // endpoint answered, so the real address is still unknown.
                Text(
                    text = stringResource(R.string.dns_diagnose_verdict_filtered_no_doh),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }
    }

    // TCP, SNI and TLS: run after DNS, against the IP DNS trusted.
    if (!state.probing && state.verdict != null) {
        Spacer(modifier = Modifier.height(16.dp))
        ItemDivider()
        Spacer(modifier = Modifier.height(16.dp))
        ConnectionSection(state = state)
    }

    // Fix: only offered when the system resolver is the problem.
    val showFix = state.verdict?.kind == DnsVerdictKind.HIJACKED ||
        state.verdict?.kind == DnsVerdictKind.FILTERED ||
        state.verdict?.kind == DnsVerdictKind.SYSTEM_DNS_FAILED
    if (showFix) {
        Spacer(modifier = Modifier.height(16.dp))
        ItemDivider()
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = stringResource(R.string.dns_diagnose_fix_title),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
        )
        Text(
            text = stringResource(R.string.dns_diagnose_fix_note),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (state.verdict?.kind == DnsVerdictKind.FILTERED) {
            Text(
                text = stringResource(R.string.dns_diagnose_fix_filtered_note),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (state.verdict?.kind == DnsVerdictKind.FILTERED &&
            state.verdict?.dohIps.isNullOrEmpty() == true
        ) {
            // The probes are one snapshot with a short timeout; DoH on a
            // filtered network is flaky, and the fix is free to try and
            // one tap to revert — so it is offered even when no DoH
            // endpoint answered in this round.
            Text(
                text = stringResource(R.string.dns_diagnose_fix_filtered_no_doh_note),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(modifier = Modifier.height(8.dp))
        // The applied state and Revert live in the block above the
        // tests now, so they are reachable whatever the verdict is.
        // This section only offers Apply when the flag is off.
        if (!state.flagOn) {
            Button(
                onClick = { onAction(DnsDiagnoseAction.ApplyFix) },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(text = stringResource(R.string.dns_diagnose_apply))
            }
            Text(
                text = stringResource(R.string.dns_diagnose_revert_note),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }

    // Core test: the real connection through the Xray core — the final
    // proof the probes cannot give. Shown once the probes finished.
    if (!state.probing && state.verdict != null) {
        Spacer(modifier = Modifier.height(16.dp))
        ItemDivider()
        Spacer(modifier = Modifier.height(16.dp))
        CoreTestSection(state = state, onAction = onAction)
    }

    // Re-test.
    Spacer(modifier = Modifier.height(24.dp))
    OutlinedButton(
        onClick = { onAction(DnsDiagnoseAction.Retest) },
        enabled = !state.probing,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text(text = stringResource(R.string.dns_diagnose_retest))
    }
    Spacer(modifier = Modifier.height(24.dp))
}

@Composable
private fun CoreTestSection(state: DnsDiagnoseUiState, onAction: (DnsDiagnoseAction) -> Unit) {
    Text(
        text = stringResource(R.string.core_test_title),
        style = MaterialTheme.typography.titleMedium,
        fontWeight = FontWeight.Bold,
    )
    Text(
        text = stringResource(R.string.core_test_desc),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Spacer(modifier = Modifier.height(8.dp))
    when (val coreTest = state.coreTest) {
        CoreTestState.Idle -> Unit
        CoreTestState.Testing -> Text(
            text = stringResource(R.string.core_test_testing),
            style = MaterialTheme.typography.bodyMedium,
        )
        is CoreTestState.Success -> Text(
            text = stringResource(R.string.core_test_success, coreTest.delayMs),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.primary,
        )
        CoreTestState.Failed -> Text(
            text = stringResource(R.string.core_test_failed),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
    Spacer(modifier = Modifier.height(8.dp))
    Button(
        onClick = { onAction(DnsDiagnoseAction.TestCore) },
        enabled = state.coreTest != CoreTestState.Testing,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Text(text = stringResource(R.string.core_test_action))
    }
    if (state.flagOn) {
        Text(
            text = stringResource(R.string.core_test_no_doh_note),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun ConnectionSection(state: DnsDiagnoseUiState) {
    Text(
        text = stringResource(R.string.conn_diagnose_title),
        style = MaterialTheme.typography.titleMedium,
        fontWeight = FontWeight.Bold,
    )
    val tcp = state.tcp
    if (tcp == null) {
        Text(
            text = stringResource(R.string.conn_diagnose_skipped),
            style = MaterialTheme.typography.bodyMedium,
        )
        return
    }
    // TCP row.
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = if (tcp.outcome == TcpOutcome.CONNECTED) "✓" else "✕",
            color = if (tcp.outcome == TcpOutcome.CONNECTED) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
            modifier = Modifier.padding(end = 8.dp),
        )
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = "TCP ${tcp.ip}:${tcp.port}",
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Bold,
            )
            Text(text = tcpOutcomeText(tcp.outcome), style = MaterialTheme.typography.bodySmall)
        }
        tcp.latencyMs?.let { latency ->
            Text(text = "$latency ms", style = MaterialTheme.typography.bodySmall)
        }
    }
    // TLS rows: only the SNI varies between them.
    state.tls.forEach { result ->
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = if (reachedServer(result)) "✓" else "✕",
                color = if (reachedServer(result)) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                modifier = Modifier.padding(end = 8.dp),
            )
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = tlsVariantText(result),
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Bold,
                )
                Text(text = tlsOutcomeText(result.outcome), style = MaterialTheme.typography.bodySmall)
                if (result.tlsVersion != null || result.negotiatedAlpn != null) {
                    Text(
                        text = listOfNotNull(result.tlsVersion, result.negotiatedAlpn).joinToString(" · "),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                result.peerCertSubject?.let { subject ->
                    Text(
                        text = subject,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            result.latencyMs?.let { latency ->
                Text(text = "$latency ms", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
    // SNI verdict.
    when (state.sniVerdict) {
        SniVerdictKind.NOT_BLOCKED -> Text(
            text = stringResource(R.string.conn_diagnose_sni_ok),
            style = MaterialTheme.typography.bodyLarge,
        )
        SniVerdictKind.FILTERED -> Text(
            text = stringResource(R.string.conn_diagnose_sni_filtered),
            style = MaterialTheme.typography.bodyLarge,
        )
        SniVerdictKind.TLS_BLOCKED -> Text(
            text = stringResource(R.string.conn_diagnose_tls_blocked),
            style = MaterialTheme.typography.bodyLarge,
        )
        SniVerdictKind.INCONCLUSIVE -> Text(
            text = stringResource(R.string.conn_diagnose_sni_inconclusive),
            style = MaterialTheme.typography.bodyLarge,
        )
        SniVerdictKind.SKIPPED, null -> Unit
    }
    if (state.tls.isNotEmpty()) {
        Text(
            text = stringResource(R.string.conn_diagnose_fingerprint_note),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
    when (state.tlsSkipped) {
        TlsSkippedReason.REALITY -> Text(
            text = stringResource(R.string.conn_diagnose_tls_skipped_reality),
            style = MaterialTheme.typography.bodyMedium,
        )
        TlsSkippedReason.NOT_TLS -> Text(
            text = stringResource(R.string.conn_diagnose_tls_skipped_no_tls),
            style = MaterialTheme.typography.bodyMedium,
        )
        null -> Unit
    }
}

@Composable
private fun tcpOutcomeText(outcome: TcpOutcome): String {
    return when (outcome) {
        TcpOutcome.CONNECTED -> stringResource(R.string.conn_diagnose_tcp_ok)
        TcpOutcome.TIMEOUT -> stringResource(R.string.dns_diagnose_error_timeout)
        TcpOutcome.REFUSED -> stringResource(R.string.conn_diagnose_tcp_refused)
        TcpOutcome.RESET -> stringResource(R.string.conn_diagnose_tcp_reset)
        TcpOutcome.NETWORK -> stringResource(R.string.dns_diagnose_error_network)
    }
}

@Composable
private fun tlsVariantText(result: TlsProbeResult): String {
    return when (result.variant) {
        TlsProbeVariant.REAL_SNI -> stringResource(R.string.conn_diagnose_sni_real, result.sni.orEmpty())
        TlsProbeVariant.HARMLESS_SNI -> stringResource(R.string.conn_diagnose_sni_harmless)
        TlsProbeVariant.NO_SNI -> stringResource(R.string.conn_diagnose_sni_none)
    }
}

@Composable
private fun tlsOutcomeText(outcome: TlsOutcome): String {
    return when (outcome) {
        TlsOutcome.HANDSHAKE_OK -> stringResource(R.string.conn_diagnose_handshake_ok)
        TlsOutcome.HANDSHAKE_FAILED -> stringResource(R.string.conn_diagnose_handshake_failed)
        TlsOutcome.TIMEOUT -> stringResource(R.string.dns_diagnose_error_timeout)
        TlsOutcome.RESET -> stringResource(R.string.conn_diagnose_tcp_reset)
        TlsOutcome.NETWORK -> stringResource(R.string.dns_diagnose_error_network)
    }
}

@Composable
private fun ProbeRow(result: DnsProbeResult) {
    val label = if (result.resolver == DnsResolver.SYSTEM) {
        stringResource(R.string.dns_diagnose_resolver_system)
    } else {
        result.resolver.displayName
    }
    val statusText = when {
        result.error != null -> stringResource(errorStringRes(result.error))
        result.ips != null -> result.ips.joinToString(", ")
        else -> ""
    }
    val answered = result.error == null && !result.ips.isNullOrEmpty()
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = if (answered) "✓" else "✕",
            color = if (answered) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
            modifier = Modifier.padding(end = 8.dp),
        )
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = label,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Bold,
            )
            Text(text = statusText, style = MaterialTheme.typography.bodySmall)
            // System DNS already asks the resolvers the active network
            // assigned (usually the ISP's); show which ones were asked,
            // so the user can see whose answers the row reports.
            if (result.resolver == DnsResolver.SYSTEM && result.queriedServers.isNotEmpty()) {
                Text(
                    text = stringResource(
                        R.string.dns_diagnose_system_resolvers,
                        result.queriedServers.joinToString(", "),
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        result.latencyMs?.let { latency ->
            Text(text = "$latency ms", style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun verdictText(verdict: DnsVerdict): String {
    return when (verdict.kind) {
        DnsVerdictKind.HEALTHY -> stringResource(R.string.dns_diagnose_verdict_healthy)
        DnsVerdictKind.HIJACKED -> stringResource(R.string.dns_diagnose_verdict_hijacked)
        DnsVerdictKind.FILTERED -> stringResource(R.string.dns_diagnose_verdict_filtered)
        DnsVerdictKind.UNRESOLVABLE -> stringResource(R.string.dns_diagnose_verdict_unresolvable)
        DnsVerdictKind.DOH_UNREACHABLE -> stringResource(R.string.dns_diagnose_verdict_doh_unreachable)
        DnsVerdictKind.SYSTEM_DNS_FAILED -> stringResource(R.string.dns_diagnose_verdict_system_failed)
    }
}

private fun errorStringRes(error: ProbeError): Int {
    return when (error) {
        ProbeError.TIMEOUT -> R.string.dns_diagnose_error_timeout
        ProbeError.NETWORK -> R.string.dns_diagnose_error_network
        ProbeError.NO_ANSWER -> R.string.dns_diagnose_error_no_answer
        ProbeError.BAD_RESPONSE -> R.string.dns_diagnose_error_bad_response
        ProbeError.NO_RESOLVER -> R.string.dns_diagnose_error_no_resolver
    }
}
