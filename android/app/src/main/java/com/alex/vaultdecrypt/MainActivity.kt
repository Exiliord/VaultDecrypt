package com.alex.vaultdecrypt

import android.Manifest
import android.app.Activity
import android.content.ContentValues
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.MediaStore
import android.provider.OpenableColumns
import android.view.View
import android.widget.Button
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStream

class MainActivity : AppCompatActivity() {

    private lateinit var btnPickFile: Button
    private lateinit var btnPickMultiple: Button
    private lateinit var tvStatus: TextView
    private lateinit var progressBar: ProgressBar

    private val MAGIC_OLD = byteArrayOf(0xFA.toByte(), 0xDA.toByte(), 0xFA.toByte(), 0xE5.toByte())
    private val MAGIC_NEW = byteArrayOf(0xFA.toByte(), 0xDD.toByte(), 0xFA.toByte(), 0xE5.toByte())
    private val XOR_KEY: Byte = 0x05
    private val JPEG_SOF2 = byteArrayOf(0xFF.toByte(), 0xC2.toByte())
    private val JPEG_SOF0 = byteArrayOf(0xFF.toByte(), 0xC0.toByte())

    private var pendingAction: (() -> Unit)? = null

    // File picker for single file
    private val pickFile = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            result.data?.data?.let { uri -> decryptFile(uri) }
        }
    }

    // File picker for multiple files
    private val pickMultipleFiles = registerForActivityResult(
        ActivityResultContracts.OpenMultipleDocuments()
    ) { uris ->
        if (uris.isNotEmpty()) decryptMultipleFiles(uris)
    }

    // Permission request launcher
    private val requestPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        val allGranted = permissions.values.all { it }
        if (allGranted) {
            pendingAction?.invoke()
        } else {
            showPermissionDeniedDialog()
        }
        pendingAction = null
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        btnPickFile = findViewById(R.id.btnPickFile)
        btnPickMultiple = findViewById(R.id.btnPickMultiple)
        tvStatus = findViewById(R.id.tvStatus)
        progressBar = findViewById(R.id.progressBar)

        // Check and request permissions on start
        checkAndRequestPermissions()

        btnPickFile.setOnClickListener {
            checkPermissionsAndRun {
                val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                    type = "*/*"
                    addCategory(Intent.CATEGORY_OPENABLE)
                }
                pickFile.launch(intent)
            }
        }

        btnPickMultiple.setOnClickListener {
            checkPermissionsAndRun {
                pickMultipleFiles.launch(arrayOf("*/*"))
            }
        }

        handleIncomingIntent(intent)
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        intent?.let { handleIncomingIntent(it) }
    }

    private fun handleIncomingIntent(intent: Intent) {
        when (intent.action) {
            Intent.ACTION_VIEW -> intent.data?.let { uri -> decryptFile(uri) }
            Intent.ACTION_SEND -> intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)?.let { uri -> decryptFile(uri) }
        }
    }

    // ==================== PERMISSIONS ====================

    private fun getRequiredPermissions(): Array<String> {
        return when {
            Build.VERSION.SDK_INT >= 33 -> {
                arrayOf(Manifest.permission.READ_MEDIA_IMAGES)
            }
            Build.VERSION.SDK_INT >= 29 -> {
                arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE)
            }
            else -> {
                arrayOf(
                    Manifest.permission.READ_EXTERNAL_STORAGE,
                    Manifest.permission.WRITE_EXTERNAL_STORAGE
                )
            }
        }
    }

    private fun checkAndRequestPermissions() {
        val permissions = getRequiredPermissions()
        val denied = permissions.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (denied.isNotEmpty()) {
            requestPermissionLauncher.launch(permissions)
        }
    }

    private fun checkPermissionsAndRun(action: () -> Unit) {
        val permissions = getRequiredPermissions()
        val denied = permissions.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }
        if (denied.isEmpty()) {
            action()
        } else {
            pendingAction = action
            requestPermissionLauncher.launch(permissions)
        }
    }

    private fun showPermissionDeniedDialog() {
        AlertDialog.Builder(this)
            .setTitle("Permisos necesarios")
            .setMessage("Se necesitan permisos de almacenamiento para desencriptar y guardar las fotos. Por favor, concede los permisos en Ajustes.")
            .setPositiveButton("OK", null)
            .show()
    }

    // ==================== FILE HELPERS ====================

    private fun getFileName(uri: Uri): String? {
        var name: String? = null
        contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) {
                val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (idx >= 0) name = cursor.getString(idx)
            }
        }
        return name ?: uri.lastPathSegment ?: "vault_file.bin"
    }

    // ==================== DECRYPTION ====================

    private fun decryptFile(uri: Uri) {
        tvStatus.text = "⏳ Procesando..."
        tvStatus.setTextColor(getColor(android.R.color.holo_orange_dark))
        progressBar.visibility = View.VISIBLE
        setButtonsEnabled(false)

        lifecycleScope.launch {
            try {
                val result = withContext(Dispatchers.IO) { performDecryption(uri) }
                tvStatus.text = result
                if (result.contains("✅")) {
                    tvStatus.setTextColor(getColor(android.R.color.holo_green_dark))
                } else {
                    tvStatus.setTextColor(getColor(android.R.color.holo_red_dark))
                }
            } catch (e: Exception) {
                tvStatus.text = "❌ Error: ${e.message}"
                tvStatus.setTextColor(getColor(android.R.color.holo_red_dark))
            } finally {
                progressBar.visibility = View.GONE
                setButtonsEnabled(true)
            }
        }
    }

    private fun decryptMultipleFiles(uris: List<Uri>) {
        tvStatus.text = "⏳ Procesando ${uris.size} archivos..."
        progressBar.visibility = View.VISIBLE
        setButtonsEnabled(false)

        lifecycleScope.launch {
            var success = 0
            var failed = 0
            var skipped = 0

            withContext(Dispatchers.IO) {
                for (uri in uris) {
                    try {
                        val result = performDecryption(uri)
                        if (result.contains("✅")) success++
                        else if (result.contains("⏭️")) skipped++
                        else failed++
                    } catch (e: Exception) { failed++ }
                }
            }

            tvStatus.text = "✅ $success desencriptados  ⏭️ $skipped omitidos  ❌ $failed errores"
            tvStatus.setTextColor(getColor(android.R.color.holo_green_dark))
            progressBar.visibility = View.GONE
            setButtonsEnabled(true)
        }
    }

    private fun setButtonsEnabled(enabled: Boolean) {
        btnPickFile.isEnabled = enabled
        btnPickMultiple.isEnabled = enabled
    }

    // ==================== CORE DECRYPTION ====================

    private fun performDecryption(uri: Uri): String {
        val fileName = getFileName(uri) ?: "unknown.bin"

        // Read file
        val data = contentResolver.openInputStream(uri)?.use { it.readBytes() }
            ?: return "❌ $fileName: No se pudo leer"

        if (data.size < 100) return "⏭️ $fileName: Archivo muy pequeño"

        // Check vault magic header
        val header = data.copyOfRange(0, 4)
        if (!header.contentEquals(MAGIC_OLD) && !header.contentEquals(MAGIC_NEW)) {
            return "⏭️ $fileName: No es vault válido"
        }

        // Find SOF2/SOF0 marker in raw data
        val sofPos = findPattern(data, JPEG_SOF2).takeIf { it >= 0 }
            ?: findPattern(data, JPEG_SOF0).takeIf { it >= 0 }
            ?: return "❌ $fileName: Sin marcador JPEG SOF"

        // Find EOI marker (last occurrence)
        var eoiPos = -1
        for (i in data.size - 2 downTo 0) {
            if (data[i] == 0xFF.toByte() && data[i + 1] == 0xD9.toByte()) {
                eoiPos = i
                break
            }
        }
        if (eoiPos == -1) return "❌ $fileName: Sin marcador JPEG EOI"

        // Build JPEG: XOR'd header + raw body
        val headerLen = sofPos
        val jpegLen = headerLen + (eoiPos - sofPos + 2)
        val jpegData = ByteArray(jpegLen)

        for (i in 0 until headerLen) {
            jpegData[i] = (data[i].toInt() xor XOR_KEY.toInt()).toByte()
        }
        System.arraycopy(data, sofPos, jpegData, headerLen, eoiPos - sofPos + 2)

        if (jpegData[0] != 0xFF.toByte() || jpegData[1] != 0xD8.toByte()) {
            return "❌ $fileName: Header inválido"
        }

        // Save to public Pictures/VaultDecrypt/
        val baseName = fileName.removeSuffix(".bin").removeSuffix(".BIN")
        val savedPath = saveToPublicStorage(jpegData, baseName)

        val sizeKb = jpegData.size / 1024.0
        return "✅ $fileName → VaultDecrypt/ (${String.format("%.1f", sizeKb)} KB)"
    }

    // ==================== SAVE TO PUBLIC STORAGE ====================

    private fun saveToPublicStorage(jpegData: ByteArray, baseName: String): String {
        val fileName = "${baseName}_decrypted.jpg"

        if (Build.VERSION.SDK_INT >= 29) {
            // Android 10+ : Use MediaStore API
            val values = ContentValues().apply {
                put(MediaStore.Images.Media.DISPLAY_NAME, fileName)
                put(MediaStore.Images.Media.MIME_TYPE, "image/jpeg")
                put(MediaStore.Images.Media.RELATIVE_PATH, Environment.DIRECTORY_PICTURES + "/VaultDecrypt")
                put(MediaStore.Images.Media.IS_PENDING, 1)
            }

            val resolver = contentResolver
            val uri = resolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, values)

            if (uri != null) {
                try {
                    resolver.openOutputStream(uri)?.use { os ->
                        os.write(jpegData)
                    }
                    values.clear()
                    values.put(MediaStore.Images.Media.IS_PENDING, 0)
                    resolver.update(uri, values, null, null)
                    return "Pictures/VaultDecrypt/$fileName"
                } catch (e: Exception) {
                    // Fallback to direct file
                }
            }
        }

        // Fallback: direct file write (Android 9 and below, or MediaStore fail)
        val picturesDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_PICTURES)
        val outputDir = File(picturesDir, "VaultDecrypt")
        if (!outputDir.exists()) outputDir.mkdirs()

        var outputFile = File(outputDir, fileName)
        var counter = 1
        while (outputFile.exists()) {
            outputFile = File(outputDir, "${baseName}_decrypted_${counter}.jpg")
            counter++
        }

        FileOutputStream(outputFile).use { it.write(jpegData) }
        return outputFile.absolutePath
    }

    // ==================== UTILITY ====================

    private fun findPattern(data: ByteArray, pattern: ByteArray): Int {
        for (i in 0..data.size - pattern.size) {
            var found = true
            for (j in pattern.indices) {
                if (data[i + j] != pattern[j]) { found = false; break }
            }
            if (found) return i
        }
        return -1
    }
}
