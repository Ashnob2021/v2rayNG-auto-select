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
            Text(
                text = stringResource(
                    R.string.dns_diagnose_verdict_hijacked_evidence,
                    verdict.systemIps.joinToString(", "),
                    verdict.dohIps.joinToString(", "),
                ),
                style = MaterialTheme.typography.bodyMedium,
            )
        }
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
        Spacer(modifier = Modifier.height(8.dp))
        if (!state.flagOn) {
            Button(
                onClick = { onAction(DnsDiagnoseAction.ApplyFix) },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(text = stringResource(R.string.dns_diagnose_apply))
            }
        } else {
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
        }
        Text(
            text = stringResource(R.string.dns_diagnose_revert_note),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (state.flagOn) {
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
