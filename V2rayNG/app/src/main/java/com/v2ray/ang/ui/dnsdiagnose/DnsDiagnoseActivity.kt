package com.v2ray.ang.ui.dnsdiagnose

import android.os.Bundle
import androidx.activity.viewModels
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.v2ray.ang.ui.base.BaseComponentActivity

class DnsDiagnoseActivity : BaseComponentActivity() {

    private val viewModel: DnsDiagnoseViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        viewModel.start(intent.getStringExtra("guid").orEmpty())
    }

    @Composable
    override fun ScreenContent() {
        val state by viewModel.uiState.collectAsStateWithLifecycle()
        DnsDiagnoseScreen(
            state = state,
            onBackClick = { finish() },
            onAction = viewModel::onAction
        )
    }
}
