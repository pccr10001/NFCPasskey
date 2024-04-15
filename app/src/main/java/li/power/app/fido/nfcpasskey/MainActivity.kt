package li.power.app.fido.nfcpasskey

import android.app.Activity
import android.app.PendingIntent
import android.content.Intent
import android.content.IntentFilter
import android.content.IntentFilter.MalformedMimeTypeException
import android.nfc.NfcAdapter
import android.nfc.tech.IsoDep
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.provider.PendingIntentHandler
import androidx.navigation.findNavController
import androidx.navigation.ui.AppBarConfiguration
import androidx.navigation.ui.navigateUp
import androidx.navigation.ui.setupActionBarWithNavController
import com.google.android.material.snackbar.Snackbar
import de.cotech.hw.SecurityKeyManager
import de.cotech.hw.SecurityKeyManagerConfig
import de.cotech.hw.fido2.PublicKeyCredential
import de.cotech.hw.fido2.PublicKeyCredentialCreate
import de.cotech.hw.fido2.internal.cbor_java.CborDecoder
import de.cotech.hw.fido2.internal.cbor_java.model.ByteString
import de.cotech.hw.fido2.internal.cbor_java.model.Map
import de.cotech.hw.fido2.internal.cbor_java.model.UnicodeString
import de.cotech.hw.fido2.internal.cose.CoseIdentifiers
import de.cotech.hw.fido2.internal.json.JsonPublicKeyCredentialSerializer
import de.cotech.hw.fido2.internal.json.JsonWebauthnOptionsParser
import de.cotech.hw.fido2.internal.webauthn.AuthenticatorDataParser
import de.cotech.hw.fido2.ui.WebauthnDialogFragment
import li.power.app.fido.nfcpasskey.databinding.ActivityMainBinding
import li.power.app.fido.nfcpasskey.service.ACTION_CREATE_PASSKEY
import li.power.app.fido.nfcpasskey.service.ACTION_GET_PASSKEY
import li.power.app.fido.nfcpasskey.service.EXTRA_TOKEN_ID
import li.power.app.fido.nfcpasskey.service.FidoCredentialProviderService
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.json.JSONArray
import org.json.JSONObject
import java.security.KeyFactory
import java.security.Security
import kotlin.io.encoding.ExperimentalEncodingApi


class MainActivity : AppCompatActivity() {

    private lateinit var appBarConfiguration: AppBarConfiguration
    private lateinit var binding: ActivityMainBinding

    private var nfcAdapter: NfcAdapter? = null
    private var pendingIntent: PendingIntent? = null
    private var intentFilters: ArrayList<IntentFilter> = ArrayList()
    private lateinit var techList: Array<Array<String>>
    private val scannedUid: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)
        binding.fab.setOnClickListener { view ->
            Snackbar.make(view, "Replace with your own action", Snackbar.LENGTH_LONG)
                .setAction("Action", null).show()
        }

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
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
    }

    override fun onPause() {
        super.onPause()
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
        intentFilters.addAll(listOf(filter))
        techList = arrayOf<Array<String>>(arrayOf<String>(IsoDep::class.java.name))
    }

    private fun enableForegroundDispatch() {
        if (nfcAdapter != null) {
            nfcAdapter!!.enableForegroundDispatch(
                this, pendingIntent,
                intentFilters.toArray() as Array<out IntentFilter>?, techList
            )
        }
    }

    private fun disableForegroundDispatch() {
        if (nfcAdapter != null) {
            nfcAdapter!!.disableForegroundDispatch(this)
        }
    }

}