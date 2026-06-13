/*
 * APK Vault / OCLC .bin Decryptor
 * ================================
 * Desencripta archivos .bin generados por apps de vault tipo APK Vault.
 * Formato: header XOR'd con 0x05 (magic FADAFAE5 + "OCLC") + datos JPEG raw.
 *
 * Uso:
 *   VaultDecrypt.exe                    (escanea carpeta actual)
 *   VaultDecrypt.exe <carpeta>          (escanea carpeta especificada)
 *   VaultDecrypt.exe archivo.bin        (desencripta un solo archivo)
 *
 * Compilar (cross-compile Linux -> Windows):
 *   x86_64-w64-mingw32-gcc -O2 -o VaultDecrypt.exe vault_decrypt.c
 *
 * Autor: Alex (OpenClaw) para Muxy
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
    #include <windows.h>
    #include <direct.h>
    #include <sys/stat.h>
    #include <sys/types.h>
    #define getcwd _getcwd
    #define stat _stat
    #define S_IFDIR _S_IFDIR
    #define PATH_SEP "\\"
#else
    #include <dirent.h>
    #include <unistd.h>
    #include <sys/stat.h>
    #include <sys/types.h>
    #define PATH_SEP "/"
#endif

#define XOR_KEY       0x05
#define MAX_PATH_LEN  4096
#define MAX_FILES     4096
#define READ_BUFSIZE  (10 * 1024 * 1024)  /* 10 MB max file */

static const unsigned char VAULT_MAGIC_OLD[4] = {0xFA, 0xDA, 0xFA, 0xE5};
static const unsigned char VAULT_MAGIC_NEW[4] = {0xFA, 0xDD, 0xFA, 0xE5};
static const unsigned char JPEG_SOF2[2]   = {0xFF, 0xC2};
static const unsigned char JPEG_SOF0[2]   = {0xFF, 0xC0};
static const unsigned char JPEG_EOI[2]    = {0xFF, 0xD9};

/* Case-insensitive string compare */
static int strcasecmp_custom(const char *a, const char *b) {
    while (*a && *b) {
        char ca = (*a >= 'A' && *a <= 'Z') ? *a + 32 : *a;
        char cb = (*b >= 'B' && *b <= 'Z') ? *b + 32 : *b;
        if (ca != cb) return (int)ca - (int)cb;
        a++; b++;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

/* Check if filename ends with .bin (case insensitive) */
static int is_bin_file(const char *filename) {
    size_t len = strlen(filename);
    if (len < 4) return 0;
    const char *ext = filename + len - 4;
    return (strcasecmp_custom(ext, ".bin") == 0);
}

/* Search for a 2-byte pattern in data */
static long find_pattern(const unsigned char *data, long data_len,
                         const unsigned char *pattern, int pat_len) {
    long i;
    for (i = 0; i <= data_len - pat_len; i++) {
        if (memcmp(data + i, pattern, pat_len) == 0)
            return i;
    }
    return -1;
}

/* Decrypt a single .bin file */
static int decrypt_file(const char *filepath, const char *output_dir) {
    FILE *fin = NULL, *fout = NULL;
    unsigned char *data = NULL;
    unsigned char *jpeg_data = NULL;
    long file_len, sof2_pos, eoi_pos;
    char out_path[MAX_PATH_LEN];
    char *basename_ptr = NULL;
    const char *filename;
    int result = 0;
    long i, header_len, jpeg_len;

    /* Open input file */
    fin = fopen(filepath, "rb");
    if (!fin) {
        printf("  [ERROR] No se pudo abrir: %s\n", filepath);
        return -1;
    }

    /* Get file size */
    fseek(fin, 0, SEEK_END);
    file_len = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    if (file_len < 100) {
        printf("  [SKIP] Archivo muy pequeño (%ld bytes)\n", file_len);
        fclose(fin);
        return -2;
    }

    /* Read entire file */
    data = (unsigned char *)malloc(file_len);
    if (!data) {
        printf("  [ERROR] Sin memoria para leer archivo\n");
        fclose(fin);
        return -1;
    }
    if ((long)fread(data, 1, file_len, fin) != file_len) {
        printf("  [ERROR] Error leyendo archivo\n");
        free(data);
        fclose(fin);
        return -1;
    }
    fclose(fin);

    /* Check vault magic header */
    if (memcmp(data, VAULT_MAGIC_OLD, 4) != 0 && memcmp(data, VAULT_MAGIC_NEW, 4) != 0) {
        printf("  [SKIP] No es archivo vault valido (header: %02X %02X %02X %02X)\n",
               data[0], data[1], data[2], data[3]);
        free(data);
        return -2;
    }

    /* Find SOF2 / SOF0 marker in raw data */
    sof2_pos = find_pattern(data, file_len, JPEG_SOF2, 2);
    if (sof2_pos == -1)
        sof2_pos = find_pattern(data, file_len, JPEG_SOF0, 2);
    if (sof2_pos == -1) {
        printf("  [ERROR] No se encontro marcador JPEG SOF\n");
        free(data);
        return -1;
    }

    /* Find EOI marker (last occurrence) */
    eoi_pos = -1;
    for (i = file_len - 2; i >= 0; i--) {
        if (data[i] == 0xFF && data[i + 1] == 0xD9) {
            eoi_pos = i;
            break;
        }
    }
    if (eoi_pos == -1) {
        printf("  [ERROR] No se encontro marcador JPEG EOI\n");
        free(data);
        return -1;
    }

    header_len = sof2_pos;
    jpeg_len = header_len + (eoi_pos - sof2_pos + 2);

    /* Build output JPEG: XOR'd header + raw JPEG body */
    jpeg_data = (unsigned char *)malloc(jpeg_len);
    if (!jpeg_data) {
        printf("  [ERROR] Sin memoria\n");
        free(data);
        return -1;
    }

    /* XOR the header portion */
    for (i = 0; i < header_len; i++) {
        jpeg_data[i] = data[i] ^ XOR_KEY;
    }

    /* Copy raw JPEG body (SOF2 to EOI inclusive) */
    memcpy(jpeg_data + header_len, data + sof2_pos, eoi_pos - sof2_pos + 2);

    /* Validate */
    if (jpeg_data[0] != 0xFF || jpeg_data[1] != 0xD8) {
        printf("  [ERROR] Header decodificado invalido\n");
        free(data);
        free(jpeg_data);
        return -1;
    }

    /* Build output filename */
    /* Extract basename */
#ifdef _WIN32
    basename_ptr = strrchr(filepath, '\\');
    if (!basename_ptr) basename_ptr = strrchr(filepath, '/');
#else
    basename_ptr = strrchr(filepath, '/');
    if (!basename_ptr) basename_ptr = strrchr(filepath, '\\');
#endif
    filename = basename_ptr ? basename_ptr + 1 : filepath;

    /* Remove .bin extension and add _decrypted.jpg */
    {
        size_t namelen = strlen(filename);
        char name_no_ext[MAX_PATH_LEN];
        /* Remove .bin (4 chars) */
        memcpy(name_no_ext, filename, namelen - 4);
        name_no_ext[namelen - 4] = '\0';

        if (output_dir && strlen(output_dir) > 0) {
            snprintf(out_path, MAX_PATH_LEN, "%s%s%s_decrypted.jpg",
                     output_dir, PATH_SEP, name_no_ext);
        } else {
            /* Same directory as input */
            char *last_sep = strrchr(filepath, '/');
            if (!last_sep) last_sep = strrchr(filepath, '\\');
            if (last_sep) {
                size_t dir_len = (size_t)(last_sep - filepath);
                char dir[MAX_PATH_LEN];
                memcpy(dir, filepath, dir_len);
                dir[dir_len] = '\0';
                snprintf(out_path, MAX_PATH_LEN, "%s%s%s_decrypted.jpg",
                         dir, PATH_SEP, name_no_ext);
            } else {
                snprintf(out_path, MAX_PATH_LEN, "%s_decrypted.jpg", name_no_ext);
            }
        }
    }

    /* Avoid overwriting existing files */
    {
        char final_path[MAX_PATH_LEN];
        int counter = 1;
        strncpy(final_path, out_path, MAX_PATH_LEN - 1);
        final_path[MAX_PATH_LEN - 1] = '\0';

        while ((fout = fopen(final_path, "rb")) != NULL) {
            fclose(fout);
            /* File exists, add counter */
            char *dot = strrchr(final_path, '.');
            if (dot) {
                size_t baselen = (size_t)(dot - final_path);
                char base[MAX_PATH_LEN];
                memcpy(base, final_path, baselen);
                base[baselen] = '\0';
                snprintf(final_path, MAX_PATH_LEN, "%s_%d.jpg", base, counter);
            } else {
                snprintf(final_path, MAX_PATH_LEN, "%s_%d.jpg", out_path, counter);
            }
            counter++;
        }
        fout = fopen(final_path, "wb");
    }

    if (!fout) {
        printf("  [ERROR] No se pudo crear: %s\n", out_path);
        free(data);
        free(jpeg_data);
        return -1;
    }

    fwrite(jpeg_data, 1, jpeg_len, fout);
    fclose(fout);

    printf("  [OK] %s -> %s (%.1f KB)\n",
           filename, strrchr(out_path, '/') ? strrchr(out_path, '/') + 1 :
           (strrchr(out_path, '\\') ? strrchr(out_path, '\\') + 1 : out_path),
           jpeg_len / 1024.0);

    result = 0;
    free(data);
    free(jpeg_data);
    return result;
}

#ifdef _WIN32
/* Windows: use FindFirstFile/FindNextFile to enumerate .bin files */
static int scan_directory_win(const char *dir) {
    char search_path[MAX_PATH_LEN];
    char filepath[MAX_PATH_LEN];
    WIN32_FIND_DATA fdata;
    HANDLE hFind;
    int total = 0, success = 0, failed = 0, skipped = 0;

    snprintf(search_path, MAX_PATH_LEN, "%s\\*.bin", dir);

    hFind = FindFirstFile(search_path, &fdata);
    if (hFind == INVALID_HANDLE_VALUE) {
        /* Try uppercase */
        snprintf(search_path, MAX_PATH_LEN, "%s\\*.BIN", dir);
        hFind = FindFirstFile(search_path, &fdata);
        if (hFind == INVALID_HANDLE_VALUE) {
            printf("  No se encontraron archivos .bin en esta carpeta.\n");
            return 0;
        }
    }

    do {
        if (fdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        snprintf(filepath, MAX_PATH_LEN, "%s\\%s", dir, fdata.cFileName);

        if (!is_bin_file(fdata.cFileName)) continue;

        total++;
        int ret = decrypt_file(filepath, dir);
        if (ret == 0) success++;
        else if (ret == -2) skipped++;
        else failed++;

    } while (FindNextFile(hFind, &fdata));

    FindClose(hFind);

    printf("\n  Resultado: %d desencriptados, %d errores, %d omitidos\n",
           success, failed, skipped);
    return total;
}
#else
/* Linux/macOS: use opendir/readdir */
static int scan_directory_unix(const char *dir) {
    DIR *d;
    struct dirent *entry;
    struct stat st;
    char filepath[MAX_PATH_LEN];
    int total = 0, success = 0, failed = 0, skipped = 0;

    d = opendir(dir);
    if (!d) {
        printf("  [ERROR] No se pudo abrir la carpeta: %s\n", dir);
        return -1;
    }

    while ((entry = readdir(d)) != NULL) {
        if (!is_bin_file(entry->d_name)) continue;

        snprintf(filepath, MAX_PATH_LEN, "%s/%s", dir, entry->d_name);

        if (stat(filepath, &st) != 0) continue;
        if (!S_ISREG(st.st_mode)) continue;

        total++;
        int ret = decrypt_file(filepath, dir);
        if (ret == 0) success++;
        else if (ret == -2) skipped++;
        else failed++;
    }

    closedir(d);

    if (total == 0) {
        printf("  No se encontraron archivos .bin en esta carpeta.\n");
    } else {
        printf("\n  Resultado: %d desencriptados, %d errores, %d omitidos\n",
               success, failed, skipped);
    }
    return total;
}
#endif

static void print_banner(void) {
    printf("============================================================\n");
    printf("  APK Vault / OCLC .bin Decryptor\n");
    printf("  por Alex (OpenClaw)\n");
    printf("============================================================\n");
    printf("\n");
}

int main(int argc, char *argv[]) {
    char target[MAX_PATH_LEN];
    int is_dir;

    print_banner();

    if (argc > 1) {
        strncpy(target, argv[1], MAX_PATH_LEN - 1);
        target[MAX_PATH_LEN - 1] = '\0';
    } else {
        if (!getcwd(target, MAX_PATH_LEN)) {
            printf("  [ERROR] No se pudo obtener la carpeta actual.\n");
            return 1;
        }
    }

    /* Check if target is a file or directory */
    {
        struct stat st;
        if (stat(target, &st) != 0) {
            printf("  [ERROR] '%s' no existe o no es accesible.\n", target);
            return 1;
        }
#ifdef _WIN32
        is_dir = (st.st_mode & _S_IFDIR) != 0;
#else
        is_dir = S_ISDIR(st.st_mode);
#endif
    }

    printf("  Carpeta: %s\n", target);

    {
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        printf("  Fecha: %04d-%02d-%02d %02d:%02d:%02d\n",
               t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
               t->tm_hour, t->tm_min, t->tm_sec);
    }
    printf("\n");

    if (is_dir) {
#ifdef _WIN32
        scan_directory_win(target);
#else
        scan_directory_unix(target);
#endif
    } else {
        /* Single file */
        int ret = decrypt_file(target, NULL);
        if (ret == 0)
            printf("\n  Listo!\n");
        else
            printf("\n  Error al procesar.\n");
    }

    printf("\n  Las imagenes se guardaron en la misma carpeta.\n");
    printf("  Nombre original + '_decrypted.jpg'\n\n");

#ifdef _WIN32
    printf("  Presiona Enter para salir...");
    getchar();
#endif

    return 0;
}
