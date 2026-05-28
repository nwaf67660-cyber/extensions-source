package eu.kanade.tachiyomi.lib.cloudflareinterceptor

import android.annotation.SuppressLint
import android.app.Application
import android.os.Handler
import android.os.Looper
import android.webkit.CookieManager
import android.webkit.JavascriptInterface
import android.webkit.WebView
import android.webkit.WebViewClient
import okhttp3.Cookie
import okhttp3.HttpUrl
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import uy.kohesive.injekt.injectLazy
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * OkHttp interceptor that resolves Cloudflare challenges using WebView.
 * Detects Cloudflare 403/503 responses and automatically handles the challenge.
 */
class CloudflareInterceptor(private val client: OkHttpClient) : Interceptor {

    private val context: Application by injectLazy()
    private val handler by lazy { Handler(Looper.getMainLooper()) }

    @Synchronized
    override fun intercept(chain: Interceptor.Chain): Response {
        val originalRequest = chain.request()
        val originalResponse = chain.proceed(originalRequest)

        // If not a Cloudflare challenge, return response as-is
        if (!isCloudflareChallenge(originalResponse)) {
            return originalResponse
        }

        return try {
            // Close original response to prevent resource leaks
            originalResponse.close()
            val resolvedRequest = resolveWithWebView(originalRequest)
            chain.proceed(resolvedRequest)
        } catch (e: Exception) {
            // Wrap exception as IOException for OkHttp compatibility
            throw IOException("Cloudflare challenge resolution failed for ${originalRequest.url}", e)
        }
    }

    /**
     * Determines if the response is a Cloudflare challenge.
     * Checks for specific error codes (403, 503) and Cloudflare server headers.
     */
    private fun isCloudflareChallenge(response: Response): Boolean {
        return response.code in ERROR_CODES &&
            response.header("Server") in SERVER_CHECK
    }

    /**
     * JavaScript interface for WebView to communicate completion.
     */
    class CloudflareJSI(private val latch: CountDownLatch) {
        @JavascriptInterface
        fun leave() = latch.countDown()
    }

    /**
     * Resolves Cloudflare challenge using WebView.
     * Loads the page and executes JavaScript to handle the challenge.
     */
    @SuppressLint("SetJavaScriptEnabled")
    private fun resolveWithWebView(request: Request): Request {
        val latch = CountDownLatch(1)
        val jsInterface = CloudflareJSI(latch)

        var webView: WebView? = null

        val origRequestUrl = request.url.toString()
        val headers = request.headers
            .toMultimap()
            .mapValues { it.value.firstOrNull().orEmpty() }
            .toMutableMap()

        handler.post {
            val wv = WebView(context).also { webView = it }
            wv.settings.apply {
                javaScriptEnabled = true
                domStorageEnabled = true
                databaseEnabled = true
                useWideViewPort = true
                loadWithOverviewMode = false
                userAgentString = request.header("User-Agent") ?: DEFAULT_USER_AGENT
            }
            wv.addJavascriptInterface(jsInterface, "CloudflareJSI")
            wv.webViewClient = object : WebViewClient() {
                override fun onPageFinished(view: WebView?, url: String?) {
                    view?.evaluateJavascript(CHECK_SCRIPT) {}
                }
            }
            wv.loadUrl(origRequestUrl, headers)
        }

        // Wait for challenge resolution or timeout
        latch.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)

        // Cleanup WebView
        handler.post {
            webView?.run {
                stopLoading()
                destroy()
            }
            webView = null
        }

        val cookies = parseCookiesFromWebView(request)

        // Save cookies to client cookie jar
        if (cookies.isNotEmpty()) {
            val cookiesByDomain = cookies.groupBy { it.domain }
            cookiesByDomain.forEach { (domain, domainCookies) ->
                client.cookieJar.saveFromResponse(
                    url = HttpUrl.Builder()
                        .scheme("https")
                        .host(domain)
                        .build(),
                    cookies = domainCookies,
                )
            }
        }

        return createRequestWithCookies(request, cookies)
    }

    /**
     * Extracts cookies from WebView safely.
     */
    private fun parseCookiesFromWebView(request: Request): List<Cookie> {
        return CookieManager.getInstance()
            ?.getCookie(request.url.toString())
            ?.split(";")
            ?.mapNotNull { Cookie.parse(request.url, it.trim()) }
            ?: emptyList()
    }

    /**
     * Creates a new request with cookies from WebView.
     * Merges existing cookies with newly obtained ones.
     */
    private fun createRequestWithCookies(request: Request, cookies: List<Cookie>): Request {
        val matchingCookies = cookies.filter { it.matches(request.url) }

        val existingCookies = request.header("Cookie")
            ?.split(";")
            ?.mapNotNull { cookieStr ->
                val parts = cookieStr.trim().split("=", limit = 2)
                if (parts.size == 2) {
                    Cookie.Builder()
                        .domain(request.url.host)
                        .name(parts[0])
                        .value(parts[1])
                        .build()
                } else null
            }
            ?: emptyList()

        val filteredExisting = existingCookies.filter { existing ->
            matchingCookies.none { new -> new.name == existing.name }
        }

        val mergedCookies = filteredExisting + matchingCookies
        return request.newBuilder()
            .header("Cookie", mergedCookies.joinToString("; ") { "${it.name}=${it.value}" })
            .build()
    }

    companion object {
        private val ERROR_CODES = listOf(403, 503)
        private val SERVER_CHECK = arrayOf("cloudflare-nginx", "cloudflare")

        private const val TIMEOUT_SECONDS = 30L

        private const val DEFAULT_USER_AGENT =
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " +
                "(KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36"

        /**
         * JavaScript code to handle Cloudflare challenges.
         * Automatically clicks simple challenge buttons and hCaptcha checkboxes.
         */
        private val CHECK_SCRIPT = """
            setInterval(() => {
                if (document.querySelector("#challenge-form") != null) {
                    const simpleChallenge = document.querySelector(
                        "#challenge-stage > div > input[type='button']"
                    );
                    if (simpleChallenge != null) simpleChallenge.click();

                    const turnstile = document.querySelector("div.hcaptcha-box > iframe");
                    if (turnstile != null) {
                        const button = turnstile.contentWindow.document.querySelector(
                            "input[type='checkbox']"
                        );
                        if (button != null) button.click();
                    }
                } else {
                    CloudflareJSI.leave();
                }
            }, 2500);
        """.trimIndent()
    }
}
