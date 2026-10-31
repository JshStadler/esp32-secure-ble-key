package dev.logiclabs.remotekey

import android.content.Context
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import kotlin.math.ceil

/** Keeps the action beside the details when they fit, or below them at larger text sizes. */
internal class DeviceCardLayout(
    context: Context,
    private val details: View,
    private val action: Button,
    private val status: TextView,
) : LinearLayout(context) {
    init {
        gravity = Gravity.CENTER_VERTICAL
        minimumHeight = dp(108)
        setPadding(dp(16), dp(12), dp(12), dp(12))
        addView(details, LayoutParams(0, LayoutParams.WRAP_CONTENT, 1f))
        addView(action, LayoutParams(dp(100), LayoutParams.WRAP_CONTENT))
        action.minimumHeight = dp(52)
    }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        action.measure(MeasureSpec.makeMeasureSpec(0, MeasureSpec.UNSPECIFIED),
            MeasureSpec.makeMeasureSpec(0, MeasureSpec.UNSPECIFIED))
        val actionWidth = maxOf(dp(100), action.measuredWidth)
        val width = MeasureSpec.getSize(widthMeasureSpec) - paddingLeft - paddingRight
        // Use the actual scaled font metrics, including Android's nonlinear font scaling.
        val labelWidth = maxOf(dp(110), ceil(status.paint.measureText("Reconnecting…") * 1.1f).toInt())
        val stacked = width - dp(48 + 14 + 8) - actionWidth < labelWidth
        orientation = if (stacked) VERTICAL else HORIZONTAL
        (details.layoutParams as LayoutParams).apply {
            this.width = if (stacked) LayoutParams.MATCH_PARENT else 0
            weight = if (stacked) 0f else 1f
        }
        (action.layoutParams as LayoutParams).apply {
            this.width = if (stacked) LayoutParams.MATCH_PARENT else actionWidth
            topMargin = if (stacked) dp(12) else 0
        }
        super.onMeasure(widthMeasureSpec, heightMeasureSpec)
    }

    private fun dp(value: Int) = (value * resources.displayMetrics.density).toInt()
}
