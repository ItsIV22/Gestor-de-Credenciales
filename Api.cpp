/**
 * @file Api.cpp
 * @brief Implementación de funciones para verificar contraseñas usando la API de Have I Been Pwned
 */

#include <iostream>
#include <sstream>
#include <iomanip>
#include <string>
#include <openssl/sha.h>
#include <curl/curl.h>
#include <algorithm>

using namespace std;

/**
 * @brief Calcula el hash SHA-1 de una cadena
 * @param input Cadena de entrada
 * @return Hash SHA-1 en formato hexadecimal
 */
string sha1(const string& input) {
    unsigned char hash[SHA_DIGEST_LENGTH];  // SHA_DIGEST_LENGTH = 20 bytes
    SHA1(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);

    stringstream ss;
    for (int i = 0; i < SHA_DIGEST_LENGTH; ++i) {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();  // Retorna el hash en formato hexadecimal
}

/**
 * @brief Callback para manejar las respuestas de cURL
 * @param contents Contenido recibido
 * @param size Tamaño de cada elemento
 * @param nmemb Número de elementos
 * @param userp Puntero al buffer de usuario
 * @return Tamaño total procesado
 */
size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

/**
 * @brief Verifica si una contraseña ha sido comprometida usando la API de HIBP
 * @param sha1_hash Hash SHA-1 de la contraseña a verificar
 * @return Número de veces que la contraseña apareció en filtraciones, -1 en caso de error
 * 
 * Utiliza el método k-anonimity de HIBP para verificar contraseñas de forma segura:
 * 1. Envía solo los primeros 5 caracteres del hash
 * 2. Recibe una lista de sufijos coincidentes
 * 3. Verifica localmente si el hash completo está en la lista
 */
int checkPassword(const string& sha1_hash) {
    string prefix = sha1_hash.substr(0, 5);  // Tomamos los primeros 5 caracteres
    string url = "https://api.pwnedpasswords.com/range/" + prefix; // URL de consulta

    CURL* curl = curl_easy_init();
    string response;
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");  // Evita bloqueos por HIBP
        CURLcode res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK) {
            cerr << "Error en cURL: " << curl_easy_strerror(res) << endl;
            return -1;
        }
    }

    // Buscar si el hash completo aparece en la respuesta
    string suffix = sha1_hash.substr(5);  // Los 35 caracteres restantes del hash

    // Convertir todo a mayúsculas para asegurarse de que coincide
    transform(suffix.begin(), suffix.end(), suffix.begin(), ::toupper);

    istringstream iss(response);
    string line;
    while (getline(iss, line)) {
        // La respuesta tiene el formato 'suffix: count'
        size_t pos = line.find(":");
        if (pos != string::npos) {
            string response_suffix = line.substr(0, pos); // Extraemos el sufijo
            string count_str = line.substr(pos + 1); // Extraemos el número de veces que ha sido vulnerada
            int count = stoi(count_str); // Convertimos a entero

            // Convertimos el sufijo de la respuesta a mayúsculas
            transform(response_suffix.begin(), response_suffix.end(), response_suffix.begin(), ::toupper);

            // Comparar sufijo
            if (response_suffix == suffix) {
                return count;  // Si encontramos una coincidencia, retornamos el número de veces
            }
        }
    }

    return 0;  // No se encontró el sufijo en la respuesta
}