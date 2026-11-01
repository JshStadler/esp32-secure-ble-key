package dev.logiclabs.remotekey

import android.view.View
import android.view.ViewGroup
import android.widget.ScrollView
import android.widget.TextView
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
@GraphicsMode(GraphicsMode.Mode.NATIVE)
class LogLayoutTest {
    @Test fun largeTextInNarrowPortraitKeepsFiltersAndActionsReadable() = checkLayout(320, 480)
    @Test fun largeTextInShortLandscapeKeepsTheHistoryReachable() = checkLayout(480, 320)

    private fun checkLayout(width: Int, height: Int) {
        RuntimeEnvironment.setQualifiers("w${width}dp-h${height}dp-mdpi")
        RuntimeEnvironment.setFontScale(2f)
        Robolectric.buildActivity(LogActivity::class.java).use { controller ->
            val activity = controller.setup().visible().get()
            val root = activity.findViewById<ViewGroup>(android.R.id.content).getChildAt(0)
            root.measure(View.MeasureSpec.makeMeasureSpec(width, View.MeasureSpec.EXACTLY),
                View.MeasureSpec.makeMeasureSpec(height, View.MeasureSpec.EXACTLY))
            root.layout(0, 0, width, height)
            val views = descendants(root)
            listOf("Logs", "Export", "Clear", "Diagnostics", "Operations", "Locations").forEach { name ->
                val text = views.filterIsInstance<TextView>().first { it.text.toString() == name }
                assertTrue("$name is clipped", text.layout.height <= text.height - text.compoundPaddingTop - text.compoundPaddingBottom)
            }
            val scroll = views.filterIsInstance<ScrollView>().single()
            assertTrue(scroll.getChildAt(0).height > scroll.height)
            assertTrue(views.filterIsInstance<TextView>().any { it.text.contains("No ", true) })
        }
    }

    private fun descendants(view: View): List<View> = listOf(view) +
        if (view is ViewGroup) (0 until view.childCount).flatMap { descendants(view.getChildAt(it)) } else emptyList()
}
