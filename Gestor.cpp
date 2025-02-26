#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <fstream>
#include <sqlite3.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <conio.h>
#include <windows.h>  // Para SetConsoleOutputCP
#include <algorithm>  // Para std::transform
#include "Api.cpp"

/**
 * @class Menu
 * @brief Implementa un menú interactivo con selección mediante flechas
 * 
 * Permite crear menús navegables usando las flechas del teclado y Enter para seleccionar.
 * Soporta la tecla ESC para cancelar la selección.
 */
class Menu {
    private:
        std::vector<std::string> opciones;
        std::string titulo;
        int posicion_actual;  // Nueva variable para rastrear la selección
    public:
        Menu(std::vector<std::string> opciones, std::string titulo);
        void mostrar();
        int seleccionar();
    private:
        void mostrarConSeleccion();  // Nuevo método privado
};

Menu::Menu(std::vector<std::string> opciones, std::string titulo) {
    this->opciones = opciones;
    this->titulo = titulo;
    this->posicion_actual = 0;
}

void Menu::mostrarConSeleccion() {
    system("cls");
    std::cout << titulo << std::endl;
    for (int i = 0; i < opciones.size(); i++) {
        if (i == posicion_actual) {
            std::cout << "> ";  // Indicador de selección
        } else {
            std::cout << "  ";
        }
        std::cout << opciones[i] << std::endl;
    }
}

int Menu::seleccionar() {
    char tecla;
    while (true) {
        mostrarConSeleccion();
        tecla = _getch();  // Obtiene la tecla presionada sin necesidad de Enter
        
        if (tecla == 27) {  // ESC
            return -1;
        } else if (tecla == 72) {  // Flecha arriba
            posicion_actual = (posicion_actual - 1 + opciones.size()) % opciones.size();
        } else if (tecla == 80) {  // Flecha abajo
            posicion_actual = (posicion_actual + 1) % opciones.size();
        } else if (tecla == 13) {  // Enter
            return posicion_actual;
        }
    }
}

/**
 * @class PasswordManager
 * @brief Gestor de contraseñas con encriptación y almacenamiento seguro
 * 
 * Características principales:
 * - Encriptación AES-256 para contraseñas
 * - Almacenamiento en SQLite con base de datos encriptada
 * - Verificación de contraseñas filtradas mediante API de HIBP
 * - Generación de contraseñas seguras
 * - Gestión de contraseña maestra
 */
class PasswordManager {
private:
    std::string master_password;
    sqlite3* db;
    const std::string MASTER_FILE = ".master.key";
    const std::string DB_FILE = "passwords.db";
    const std::string DB_FILE_ENC = "passwords.db.enc";
    
    /**
     * @brief Encripta texto usando AES-256-CBC
     * @param text Texto a encriptar
     * @param key Clave de encriptación
     * @return Texto encriptado
     */
    std::string encrypt(const std::string& text, const std::string& key) {
        std::string encrypted;
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        
        unsigned char key_data[32], iv[16];
        // Derivar key y IV de la contraseña maestra
        EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL,
                      (unsigned char*)key.c_str(), key.length(), 1, key_data, iv);

        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key_data, iv);
        
        std::vector<unsigned char> cipher_data(text.length() + EVP_MAX_BLOCK_LENGTH);
        int len, cipher_len;
        
        EVP_EncryptUpdate(ctx, cipher_data.data(), &len,
                         (unsigned char*)text.c_str(), text.length());
        cipher_len = len;
        
        EVP_EncryptFinal_ex(ctx, cipher_data.data() + len, &len);
        cipher_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        
        return std::string(cipher_data.begin(), cipher_data.begin() + cipher_len);
    }
    
    // Función para desencriptar texto
    std::string decrypt(const std::string& cipher_text, const std::string& key) {
        std::string decrypted;
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        
        unsigned char key_data[32], iv[16];
        EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), NULL,
                      (unsigned char*)key.c_str(), key.length(), 1, key_data, iv);

        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key_data, iv);
        
        std::vector<unsigned char> plain_data(cipher_text.length());
        int len, plain_len;
        
        EVP_DecryptUpdate(ctx, plain_data.data(), &len,
                         (unsigned char*)cipher_text.c_str(), cipher_text.length());
        plain_len = len;
        
        EVP_DecryptFinal_ex(ctx, plain_data.data() + len, &len);
        plain_len += len;
        
        EVP_CIPHER_CTX_free(ctx);
        
        return std::string(plain_data.begin(), plain_data.begin() + plain_len);
    }

    /**
     * @brief Verifica la contraseña maestra contra el archivo almacenado
     * @return true si la contraseña es correcta, false en caso contrario
     */
    bool checkMasterPassword() {
        std::ifstream file(MASTER_FILE, std::ios::binary);
        if (!file) return false;
        
        std::string stored_hash;
        std::getline(file, stored_hash);
        file.close();
        
        std::cout << "Ingrese la contraseña maestra: ";
        std::string input_password;
        std::cin >> input_password;
        
        // Almacenar la contraseña si la verificación es exitosa
        try {
            std::string decrypted = decrypt(stored_hash, input_password);
            if (decrypted == "VALID") {
                master_password = input_password;  // Guardar la contraseña válida
                return true;
            }
        } catch (...) {
            // Si hay error en el descifrado, la contraseña es incorrecta
        }
        return false;
    }

    void setupMasterPassword() {
        std::vector<std::string> opciones = {
            "Crear contraseña manualmente",
            "Generar contraseña automáticamente"
        };
        Menu menu(opciones, "Configuración de contraseña maestra");
        int opcion = menu.seleccionar();

        std::string new_master_password;
        if (opcion == 0) {
            std::cout << "Ingrese su nueva contraseña maestra: ";
            std::cin >> new_master_password;
        } else {
            new_master_password = generatePassword(12, true, true, true, true);
            std::cout << "Su contraseña maestra generada es: " << new_master_password << std::endl;
            std::cout << "¡Guárdela en un lugar seguro!" << std::endl;
            system("pause");
        }

        // Encriptar y guardar la contraseña
        std::string encrypted = encrypt("VALID", new_master_password);
        std::ofstream file(MASTER_FILE, std::ios::binary);
        file << encrypted;
        file.close();
        
        // Almacenar la contraseña maestra en la variable miembro
        master_password = new_master_password;
        
        // Hacer el archivo oculto
        SetFileAttributesA(MASTER_FILE.c_str(), FILE_ATTRIBUTE_HIDDEN);
        
        // Hacer la base de datos oculta
        SetFileAttributesA("passwords.db", FILE_ATTRIBUTE_HIDDEN);
    }

    bool verifyMasterPassword() {
        int intentos = 3;
        while (intentos > 0) {
            if (checkMasterPassword()) {
                return true;
            }
            intentos--;
            if (intentos > 0) {
                std::cout << "Contraseña incorrecta. Le quedan " << intentos << " intentos." << std::endl;
            }
        }
        std::cout << "Demasiados intentos fallidos. El programa se cerrará." << std::endl;
        return false;
    }

    void initDatabase() {
        const char* sql = "CREATE TABLE IF NOT EXISTS passwords("
                         "id INTEGER PRIMARY KEY AUTOINCREMENT,"  // Nuevo campo id
                         "service_name TEXT NOT NULL,"           // Ya no es PRIMARY KEY
                         "username TEXT NOT NULL,"
                         "encrypted_password TEXT NOT NULL,"
                         "UNIQUE(service_name, username));"      // Constraint para evitar duplicados exactos
                         "CREATE TABLE IF NOT EXISTS settings("
                         "key TEXT PRIMARY KEY,"
                         "value TEXT NOT NULL);";
        char* errMsg = 0;
        int rc = sqlite3_exec(db, sql, 0, 0, &errMsg);
        if (rc != SQLITE_OK) {
            std::cerr << "Error SQL: " << errMsg << std::endl;
            sqlite3_free(errMsg);
            system("pause");
            exit(1);
        }
    }

    /**
     * @brief Estructura para almacenar credenciales
     */
    struct Credential {
        int id;              ///< ID único en la base de datos
        std::string service; ///< Nombre del servicio
        std::string username; ///< Nombre de usuario
    };

    std::vector<Credential> getStoredCredentials() {
        std::vector<Credential> credentials;
        const char* sql = "SELECT id, service_name, username FROM passwords ORDER BY service_name, username;";
        sqlite3_stmt* stmt;
        
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                Credential cred;
                cred.id = sqlite3_column_int(stmt, 0);
                cred.service = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                cred.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
                credentials.push_back(cred);
            }
        }
        sqlite3_finalize(stmt);
        return credentials;
    }

    void deleteCredentials() {
        std::vector<Credential> credentials = getStoredCredentials();
        if (credentials.empty()) {
            std::cout << "No hay credenciales almacenadas." << std::endl;
            system("pause");
            return;
        }

        std::vector<std::string> menuOptions;
        for (const auto& cred : credentials) {
            menuOptions.push_back(cred.service + " - " + cred.username);
        }
        menuOptions.push_back("Cancelar");

        Menu menu(menuOptions, "Seleccione las credenciales a eliminar:");
        int choice = menu.seleccionar();

        if (choice == menuOptions.size() - 1) {  // Si seleccionó "Cancelar"
            return;
        }

        const char* sql = "DELETE FROM passwords WHERE id = ?;";
        sqlite3_stmt* stmt;
        
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, credentials[choice].id);
            
            if (sqlite3_step(stmt) == SQLITE_DONE) {
                std::cout << "Credenciales eliminadas exitosamente!" << std::endl;
            } else {
                std::cout << "Error al eliminar las credenciales." << std::endl;
            }
            system("pause");
        }
        sqlite3_finalize(stmt);
    }

    std::string getValidInput(const std::string& prompt) {
        std::string input;
        while (true) {
            std::cout << prompt;
            std::getline(std::cin, input);
            
            // Verificar si se presionó ESC
            if (_kbhit() && _getch() == 27) {
                throw std::runtime_error("Operación cancelada");
            }
            
            // Eliminar espacios en blanco al inicio y final
            input.erase(0, input.find_first_not_of(" \t\n\r\f\v"));
            input.erase(input.find_last_not_of(" \t\n\r\f\v") + 1);
            
            if (!input.empty()) {
                return input;
            }
            std::cout << "El campo no puede estar vacío. Intente de nuevo." << std::endl;
        }
    }

    int getValidNumber(const std::string& prompt, int min, int max) {
        while (true) {
            std::string input;
            std::cout << prompt;
            std::getline(std::cin, input);
            
            // Verificar si se presionó ESC
            if (_kbhit() && _getch() == 27) {
                throw std::runtime_error("Operación cancelada");
            }

            try {
                int number = std::stoi(input);
                if (number >= min && number <= max) {
                    return number;
                }
            } catch (...) {
                // Captura cualquier error de conversión
            }
            std::cout << "Por favor ingrese un número válido entre " << min << " y " << max << std::endl;
        }
    }

    // Añadir estos nuevos métodos privados
    void encryptFile(const std::string& input_file, const std::string& output_file) {
        std::ifstream inFile(input_file, std::ios::binary);
        std::vector<char> buffer(std::istreambuf_iterator<char>(inFile), {});
        inFile.close();
        
        std::string encrypted = encrypt(std::string(buffer.begin(), buffer.end()), master_password);
        
        std::ofstream outFile(output_file, std::ios::binary);
        outFile.write(encrypted.c_str(), encrypted.size());
        outFile.close();
    }
    
    void decryptFile(const std::string& input_file, const std::string& output_file) {
        std::ifstream inFile(input_file, std::ios::binary);
        std::vector<char> buffer(std::istreambuf_iterator<char>(inFile), {});
        inFile.close();
        
        std::string decrypted = decrypt(std::string(buffer.begin(), buffer.end()), master_password);
        
        std::ofstream outFile(output_file, std::ios::binary);
        outFile.write(decrypted.c_str(), decrypted.size());
        outFile.close();
    }

    void checkPasswordBreaches(int id) {
        const char* sql = "SELECT service_name, username, encrypted_password FROM passwords WHERE id = ?;";
        sqlite3_stmt* stmt;
        
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, id);
            
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                std::string service = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                std::string username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                std::string encrypted_password = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
                
                // Desencriptar la contraseña
                std::string password = decrypt(encrypted_password, master_password);
                
                // Generar el hash SHA-1 y convertirlo a mayúsculas
                std::string hash = sha1(password);
                std::transform(hash.begin(), hash.end(), hash.begin(), ::toupper);
                
                // Verificar el hash con la API
                int breachCount = checkPassword(hash);
                if (breachCount > 0) {
                    std::cout << "\nALERTA: La contraseña para " << service << " (usuario: " << username << ") "
                              << "ha aparecido en " << breachCount << " filtraciones de datos." << std::endl;
                    std::cout << "Se recomienda cambiar esta contraseña inmediatamente." << std::endl;
                } else if (breachCount == 0) {
                    std::cout << "\nLa contraseña para " << service << " (usuario: " << username << ") "
                              << "no se ha encontrado en ninguna filtración conocida." << std::endl;
                } else {
                    std::cout << "\nError al verificar la contraseña. Por favor, intente más tarde." << std::endl;
                }
            }
        }
        sqlite3_finalize(stmt);
        system("pause");
    }

    void checkAllPasswords() {
        std::cout << "\nVerificando todas las contraseñas almacenadas..." << std::endl;
        const char* sql = "SELECT id, service_name, username, encrypted_password FROM passwords;";
        sqlite3_stmt* stmt;
        bool foundBreaches = false;
        
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, 0) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                int id = sqlite3_column_int(stmt, 0);
                std::string service = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                std::string username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
                std::string encrypted_password = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
                
                // Desencriptar la contraseña
                std::string password = decrypt(encrypted_password, master_password);
                
                // Generar el hash SHA-1 y convertirlo a mayúsculas
                std::string hash = sha1(password);
                std::transform(hash.begin(), hash.end(), hash.begin(), ::toupper);
                
                // Verificar el hash con la API
                int breachCount = checkPassword(hash);
                if (breachCount > 0) {
                    foundBreaches = true;
                    std::cout << "\nALERTA: La contraseña para " << service << " (usuario: " << username << ") "
                              << "ha aparecido en " << breachCount << " filtraciones de datos." << std::endl;
                }
            }
            
            if (!foundBreaches) {
                std::cout << "\nNinguna de las contraseñas almacenadas se ha encontrado en filtraciones conocidas." << std::endl;
            }
        }
        sqlite3_finalize(stmt);
        system("pause");
    }

public:
    PasswordManager() {
        // Verificar si el archivo master existe primero
        std::ifstream file(MASTER_FILE, std::ios::binary);
        bool first_time = !file.good();
        file.close();

        if (first_time) {
            std::cout << "Primera vez: Configuración de contraseña maestra" << std::endl;
            setupMasterPassword();
        } else if (!verifyMasterPassword()) {
            exit(1);  // Salir si la contraseña es incorrecta
        }

        // Verificar si existe el archivo encriptado
        if (std::ifstream(DB_FILE_ENC)) {
            try {
                // Intentar desencriptar directamente ya que tenemos la contraseña maestra
                decryptFile(DB_FILE_ENC, DB_FILE);
                remove(DB_FILE_ENC.c_str());
            } catch (const std::exception& e) {
                std::cerr << "Error al desencriptar la base de datos: " << e.what() << std::endl;
                system("pause");
                exit(1);
            }
        }

        int rc = sqlite3_open(DB_FILE.c_str(), &db);
        if (rc) {
            std::cerr << "No se puede abrir la base de datos: " << sqlite3_errmsg(db) << std::endl;
            system("pause");
            exit(1);
        }
        
        SetFileAttributesA(DB_FILE.c_str(), FILE_ATTRIBUTE_HIDDEN);
        initDatabase();
    }

    std::string generatePassword(int length, bool useLower, bool useUpper, bool useNumbers, bool useSpecial) {
        std::string charset;
        if (useLower) charset += "abcdefghijklmnopqrstuvwxyz";
        if (useUpper) charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        if (useNumbers) charset += "0123456789";
        if (useSpecial) charset += "!@#$%^&*()_+-=[]{}|;:,.<>?";

        std::random_device rd;
        std::mt19937 generator(rd());
        std::uniform_int_distribution<int> distribution(0, charset.size() - 1);

        std::string password;
        for (int i = 0; i < length; ++i) {
            password += charset[distribution(generator)];
        }
        return password;
    }

    bool savePassword(const std::string& service_name, const std::string& username, const std::string& password) {
        std::string encrypted_password = encrypt(password, master_password);

        const char* sql = "INSERT INTO passwords (service_name, username, encrypted_password) "
                         "VALUES (?, ?, ?);";
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
        
        if (rc != SQLITE_OK) {
            return false;
        }

        sqlite3_bind_text(stmt, 1, service_name.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, username.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, encrypted_password.c_str(), -1, SQLITE_STATIC);

        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        if (rc == SQLITE_CONSTRAINT) {
            std::cout << "Ya existe una cuenta con ese nombre de usuario para este servicio." << std::endl;
            return false;
        }

        return rc == SQLITE_DONE;
    }

    void showPasswords() {
        const char* sql = "SELECT service_name, username, encrypted_password FROM passwords ORDER BY service_name, username;";
        sqlite3_stmt* stmt;
        int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
        
        if (rc != SQLITE_OK) {
            std::cout << "Error al recuperar contraseñas" << std::endl;
            return;
        }

        std::cout << "\nContraseñas guardadas:\n" << std::endl;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            std::string service = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            std::string username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            std::string encrypted_password = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            
            // Desencriptar la contraseña antes de mostrarla
            std::string decrypted_password = decrypt(encrypted_password, master_password);
            
            std::cout << "Servicio: " << service << "\nUsuario: " << username 
                     << "\nContraseña: " << decrypted_password << "\n" << std::endl;
        }
        
        sqlite3_finalize(stmt);
        system("pause");
    }

    void showMenu() {
        while (true) {
            std::vector<std::string> opciones = {
                "Generar nueva contraseña",
                "Almacenar credenciales",
                "Ver contraseñas guardadas",
                "Eliminar credenciales",
                "Verificar contraseña específica",
                "Verificar todas las contraseñas",
                "Salir y encriptar base de datos"
            };
            Menu menu(opciones, "=== Gestor de Contraseñas ===");
            int choice = menu.seleccionar();
            
            if (choice == -1) continue;  // Si presionó ESC

            switch (choice) {
                case 0: {
                    try {
                        std::string service_name = getValidInput("Nombre del servicio: ");
                        std::string username = getValidInput("Nombre de usuario: ");
                        int length = getValidNumber("Longitud de la contraseña: ", 4, 100);

                        std::string password = generatePassword(length, true, true, true, true);
                        if (savePassword(service_name, username, password)) {
                            std::cout << "Contraseña generada y guardada exitosamente!\n";
                            std::cout << "Usuario: " << username << "\n";
                            std::cout << "Contraseña: " << password << std::endl;
                            system("pause");
                        }
                    } catch (const std::runtime_error& e) {
                        std::cout << e.what() << std::endl;
                        system("pause");
                    }
                    break;
                }
                case 1: {
                    try {
                        std::string service_name = getValidInput("Nombre del servicio: ");
                        std::string username = getValidInput("Nombre de usuario: ");
                        std::string password = getValidInput("Contraseña: ");

                        if (savePassword(service_name, username, password)) {
                            std::cout << "Credenciales guardadas exitosamente!" << std::endl;
                            system("pause");
                        }
                    } catch (const std::runtime_error& e) {
                        std::cout << e.what() << std::endl;
                        system("pause");
                    }
                    break;
                }
                case 2:
                    showPasswords();
                    break;
                case 3:
                    deleteCredentials();
                    break;
                case 4: {
                    std::vector<Credential> credentials = getStoredCredentials();
                    if (credentials.empty()) {
                        std::cout << "No hay credenciales almacenadas." << std::endl;
                        system("pause");
                        break;
                    }

                    std::vector<std::string> menuOptions;
                    for (const auto& cred : credentials) {
                        menuOptions.push_back(cred.service + " - " + cred.username);
                    }
                    menuOptions.push_back("Cancelar");

                    Menu menu(menuOptions, "Seleccione las credenciales a verificar:");
                    int subChoice = menu.seleccionar();

                    if (subChoice != menuOptions.size() - 1) {  // Si no seleccionó "Cancelar"
                        checkPasswordBreaches(credentials[subChoice].id);
                    }
                    break;
                }
                case 5:
                    checkAllPasswords();
                    break;
                case 6:
                    return;
            }
        }
    }

    ~PasswordManager() {
        if (db) {
            sqlite3_close(db);
            db = nullptr;
        }
        
        // Solo encriptar si la base de datos existe y tenemos la contraseña maestra
        if (!master_password.empty() && std::ifstream(DB_FILE)) {
            try {
                encryptFile(DB_FILE, DB_FILE_ENC);
                remove(DB_FILE.c_str());
                SetFileAttributesA(DB_FILE_ENC.c_str(), FILE_ATTRIBUTE_HIDDEN);
            } catch (const std::exception& e) {
                std::cerr << "Error al encriptar la base de datos: " << e.what() << std::endl;
                system("pause");
            }
        }
    }
};

int main() {
    SetConsoleOutputCP(CP_UTF8);  // Configurar UTF-8
    PasswordManager manager;
    manager.showMenu();
    return 0;
} 