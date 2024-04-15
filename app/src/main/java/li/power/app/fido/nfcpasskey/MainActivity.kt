package li.power.app.fido.nfcpasskey

import android.app.PendingIntent
import android.content.Intent
import android.content.IntentFilter
import android.content.IntentFilter.MalformedMimeTypeException
import android.nfc.NfcAdapter
import android.nfc.Tag

import android.nfc.tech.IsoDep
import android.os.Bundle
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.navigation.ui.AppBarConfiguration
import com.google.android.material.snackbar.Snackbar
import li.power.app.fido.nfcpasskey.databinding.ActivityMainBinding
import li.power.app.fido.nfcpasskey.model.AppDatabase
import li.power.app.fido.nfcpasskey.model.Token
import li.power.app.fido.nfcpasskey.utils.APDU
import org.apache.commons.codec.binary.Hex
import java.io.IOException
import java.util.*
import kotlin.collections.ArrayList


class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    private val TAG = "MainActivity"

    private var nfcAdapter: NfcAdapter? = null
    private var pendingIntent: PendingIntent? = null
    private lateinit var intentFilters: Array<IntentFilter>
    private lateinit var techList: Array<Array<String>>
    private var scannedUid: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)
        binding.fab.setOnClickListener { view ->
            Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
                .setAction("Action", null).show()
        }

        setupNfc()

    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        // Inflate the menu; this adds items to the action bar if it is present.
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        return when (item.itemId) {
            R.id.action_settings -> true
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun showToast(msg: String) {
        runOnUiThread { Toast.makeText(applicationContext, msg, Toast.LENGTH_SHORT).show() }
    }

    override fun onResume() {
        super.onResume()
        enableForegroundDispatch()
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        intent?.let { handleIntent(it) }
    }

    override fun onPause() {
        super.onPause()
        disableForegroundDispatch()
    }

    private fun handleIntent(intent: Intent) {
        if (NfcAdapter.ACTION_TAG_DISCOVERED == intent.action || NfcAdapter.ACTION_TECH_DISCOVERED == intent.action) {
            val tag = IsoDep.get(intent.getParcelableExtra(NfcAdapter.EXTRA_TAG, Tag::class.java))
            scannedUid = Hex.encodeHexString(tag.tag.id).uppercase(Locale.getDefault())
            Log.d(TAG, "Card detected, ID: $scannedUid")
            try {
                tag.connect()
                Log.d(TAG, "Tag connected")

                val resp = tag.transceive(APDU.selectFidoAppletCmd())
                Log.d(TAG, "Select response: " + Hex.encodeHexString(resp))
                if (resp.size < 2) {
                    return
                }

                if (resp[resp.size - 2] != 0x90.toByte() || resp[resp.size - 1].toInt() != 0x00) {
                    return
                }

                val tokenDao = AppDatabase.getDatabase(applicationContext).tokenDao
                var token: Token? = tokenDao.getTokenById(scannedUid)

                if (token == null) {
                    Log.d(TAG, "New token detected")
                    token = Token()
                    token.id = scannedUid
                    token.setName("Token-" + scannedUid!!.substring(scannedUid!!.length - 4))
                    tokenDao.insertAll(token)
                }
                Log.d(TAG, "Token " + token.name)
                tag.close()
            } catch (e: IOException) {
                throw RuntimeException(e)
            }
        }
    }

    private fun setupNfc() {
        if (nfcAdapter != null) {
            return
        }

        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        if (nfcAdapter == null) {
            showToast("No NFC supported on this phone")
            return
        }

        if (!nfcAdapter!!.isEnabled) {
            showToast("NFC Adapter is disabled")
            return
        }

        pendingIntent = PendingIntent.getActivity(
            this,
            1,
            Intent(this, this.javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_MUTABLE
        )
        val filter = IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED)
        try {
            filter.addDataType("*/*")
        } catch (e: MalformedMimeTypeException) {
            e.printStackTrace()
        }
        intentFilters = arrayOf(filter)
        techList = arrayOf(arrayOf(IsoDep::class.java.name))
    }

    private fun enableForegroundDispatch() {
        if (nfcAdapter != null) {
            nfcAdapter!!.enableForegroundDispatch(
                this, pendingIntent,
                intentFilters, techList
            )
        }
    }

    private fun disableForegroundDispatch() {
        if (nfcAdapter != null) {
            nfcAdapter!!.disableForegroundDispatch(this)
        }
    }

}