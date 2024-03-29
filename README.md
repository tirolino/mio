# mio
import msal

# Configura los detalles de la aplicación registrada en el portal de Azure
client_id = 'tu_id_de_cliente'
client_secret = 'tu_secreto_de_cliente'
authority = 'https://login.microsoftonline.com/tu_id_de_tenant'

# Configura los permisos necesarios para tu aplicación
scopes = ['https://graph.microsoft.com/.default']

# Crea una aplicación de confidencialidad de cliente
app = msal.ConfidentialClientApplication(
    client_id,
    authority=authority,
    client_credential=client_secret
)

# Intenta obtener un token de acceso
token_response = app.acquire_token_for_client(scopes)

# Verifica si se obtuvo el token correctamente
if 'access_token' in token_response:
    access_token = token_response['access_token']
    print(f'Token de acceso: {access_token}')
else:
    print('No se pudo obtener el token de acceso')


tengo un cliente programado en spring que realiza una petición SOAP firmada con RSA_SHA1 y han modificado el enpoint del servidor para que la firma se tenga que realizar con HMAC_SHA256 que cambios tengo que realizar para poder mantener la comunicación
ChatGPT
Para adaptar tu cliente Spring que realiza una petición SOAP firmada con RSA_SHA1 a HMAC_SHA256 en el servidor, deberás realizar los siguientes cambios:

Cambiar el algoritmo de firma:

En lugar de utilizar RSA_SHA1, deberás configurar el cliente para que utilice HMAC_SHA256. Esto implica cambiar la forma en que se firma la solicitud SOAP.
Actualizar las claves de firma:

RSA_SHA1 utiliza pares de claves RSA (una pública y una privada). HMAC_SHA256, por otro lado, utiliza una clave secreta compartida. Asegúrate de obtener la clave secreta compartida adecuada del servidor.
Actualizar la lógica de firma:

Modifica la lógica de firma en tu cliente Spring para utilizar el algoritmo HMAC_SHA256 en lugar de RSA_SHA1. Esto implica calcular el valor del HMAC_SHA256 utilizando la clave secreta compartida y aplicarlo a tu solicitud SOAP.
Actualizar la cabecera de la solicitud SOAP:

Asegúrate de que la cabecera de la solicitud SOAP incluya la firma HMAC_SHA256 correcta en lugar de la firma RSA_SHA1. Esto podría requerir cambios en el formato de la cabecera o en la forma en que se incluye la firma.
Validar la respuesta del servidor:

Si el servidor espera una firma HMAC_SHA256 en la solicitud, es posible que también cambie la forma en que valida la firma en la respuesta. Asegúrate de que tu cliente pueda verificar correctamente las respuestas del servidor.
Pruebas y validación:

Una vez que hayas realizado estos cambios, realiza pruebas exhaustivas para asegurarte de que la comunicación entre tu cliente y el servidor se realice de manera segura y que la firma HMAC_SHA256 funcione correctamente.
Recuerda que la forma exacta de realizar estos cambios dependerá de la implementación específica de tu cliente Spring y de cómo se gestionen las firmas en tu solicitud SOAP. Asegúrate de seguir las recomendaciones y directrices proporcionadas por la documentación del servidor y las bibliotecas de criptografía que estés utilizando en tu aplicación. Además, mantén la seguridad de las claves y asegúrate de que la comunicación sea segura en todo momento.

para el punto 3 estoy utilizando Wss4SecurityInterceptor y org.apache.cxf con la clave correcta que cambios debería realizar
ChatGPT
Si estás utilizando Wss4SecurityInterceptor de Apache CXF en tu cliente Spring para manejar la seguridad de las solicitudes SOAP y necesitas cambiar de RSA_SHA1 a HMAC_SHA256, aquí hay algunos pasos generales que podrías seguir:

Configuración de SecurityPolicy: En tu configuración de Wss4SecurityInterceptor, debes especificar el SecurityPolicy adecuado que corresponda al algoritmo HMAC_SHA256. Esto normalmente se hace a través de un archivo de configuración de políticas de seguridad (por ejemplo, un archivo .xml) que define las políticas de seguridad.

Actualización de Claves: Asegúrate de que tu aplicación tenga acceso a la clave secreta compartida que se utilizará para firmar las solicitudes. Puede ser necesario modificar la forma en que se almacenan o se obtienen estas claves, dependiendo de tu configuración.

Actualizar el Proveedor de Claves: Si antes estabas utilizando un proveedor de claves específico para RSA (por ejemplo, org.apache.wss4j.dom.WSProviderConfig), deberás cambiarlo para usar un proveedor de claves que admita HMAC_SHA256. Verifica la documentación de Apache CXF para conocer las clases y métodos específicos necesarios.

Actualización de la Lógica de Firma: Modifica la lógica que firma tus solicitudes SOAP para utilizar HMAC_SHA256 en lugar de RSA_SHA1. Esto implicará calcular un HMAC (usando la clave compartida) en lugar de una firma RSA.

Actualización de Cabeceras SOAP: Asegúrate de que la cabecera de la solicitud SOAP incluya la firma HMAC_SHA256 correcta. Puede ser necesario personalizar la creación de la cabecera SOAP para agregar la firma HMAC en el formato esperado por el servidor.

Validación de Respuestas: Asegúrate de que el cliente pueda validar correctamente las respuestas del servidor que ahora también estarán firmadas con HMAC_SHA256.

Pruebas y Depuración: Realiza pruebas exhaustivas para asegurarte de que los cambios funcionen correctamente. Utiliza herramientas de depuración y registro para verificar que las solicitudes y respuestas se estén firmando y verificando correctamente.

Seguridad de Claves: Mantén la seguridad de las claves compartidas y asegúrate de que se gestionen de manera segura en tu aplicación.

Ten en cuenta que los detalles específicos de la implementación pueden variar según la configuración de tu aplicación y la forma en que estás utilizando Apache CXF. Consulta la documentación de Apache CXF y las directrices de seguridad para obtener información detallada sobre cómo realizar estos cambios de manera efectiva. Además, es importante realizar pruebas exhaustivas para garantizar que la seguridad se mantenga en todo momento.

org.springframework.ws.soap.security.wss4j.support.CryptoFactoryBean de dónde saca los valores que tiene que aplicar
ChatGPT
org.springframework.ws.soap.security.wss4j.support.CryptoFactoryBean es una clase de Spring Web Services (Spring-WS) que se utiliza para configurar y crear instancias de objetos Crypto que son necesarios para operaciones criptográficas y de seguridad en solicitudes y respuestas SOAP. Esta clase se utiliza para definir la configuración de seguridad y las propiedades criptográficas que se utilizarán en la interacción SOAP.

Los valores que CryptoFactoryBean utiliza para configurar un objeto Crypto se definen generalmente a través de las propiedades configuradas en el bean de Spring. Estos valores pueden incluir:

Location: La ubicación del archivo de configuración de seguridad (por ejemplo, un archivo de propiedades) que contiene información sobre las claves, algoritmos y propiedades criptográficas necesarias. Puedes especificar la ubicación del archivo utilizando la propiedad location en el bean CryptoFactoryBean.

Propiedades de Criptografía: Los valores específicos para propiedades criptográficas, como algoritmos de firma, algoritmos de cifrado, ubicación de claves, etc. Estos valores se suelen especificar en el archivo de configuración de seguridad referenciado por location.

Claves y Certificados: Las claves privadas, claves públicas y certificados necesarios para las operaciones de cifrado y firma. Estos valores también se especifican en el archivo de configuración de seguridad o en el bean mismo, dependiendo de la configuración.

Configuración de Proveedor de Seguridad: Opcionalmente, la configuración del proveedor de seguridad que se utilizará para operaciones criptográficas.

En resumen, CryptoFactoryBean toma estos valores de configuración que se definen en su configuración Spring y los utiliza para crear una instancia de un objeto Crypto que se utilizará en la seguridad de las solicitudes y respuestas SOAP. La forma exacta de configurar CryptoFactoryBean y los valores que se deben proporcionar dependerá de los requisitos de seguridad específicos de tu aplicación y la infraestructura de seguridad que estés utilizando.

me puedes dar una función que escriba en el log de la aplicación todas las propiedades de la clase CryptoFactoryBean
ChatGPT
Para crear una función que escriba en el log de la aplicación todas las propiedades de una instancia de la clase CryptoFactoryBean, puedes usar reflexión para obtener dinámicamente las propiedades y sus valores. A continuación, te proporciono un ejemplo de una función en Java que hace esto utilizando la biblioteca de registro SLF4J y Logback para el registro:

Primero, asegúrate de tener las dependencias de SLF4J y Logback en tu proyecto. Puedes agregarlas a tu archivo pom.xml si estás utilizando Maven:

xml
Copy code
<dependency>
    <groupId>org.slf4j</groupId>
    <artifactId>slf4j-api</artifactId>
    <version>1.7.32</version> <!-- Asegúrate de usar la última versión disponible -->
</dependency>
<dependency>
    <groupId>ch.qos.logback</groupId>
    <artifactId>logback-classic</artifactId>
    <version>1.2.6</version> <!-- Asegúrate de usar la última versión disponible -->
</dependency>
Luego, puedes crear la función para registrar las propiedades de CryptoFactoryBean:

java
Copy code
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ws.soap.security.wss4j.support.CryptoFactoryBean;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

public class CryptoFactoryBeanLogger {

    private static final Logger logger = LoggerFactory.getLogger(CryptoFactoryBeanLogger.class);

    public static void logCryptoFactoryBeanProperties(CryptoFactoryBean cryptoFactoryBean) {
        if (cryptoFactoryBean == null) {
            logger.warn("CryptoFactoryBean is null");
            return;
        }

        logger.info("CryptoFactoryBean properties:");

        try {
            // Obtener todas las propiedades de la clase CryptoFactoryBean utilizando reflexión
            Class<?> clazz = CryptoFactoryBean.class;
            Field[] fields = clazz.getDeclaredFields();

            Map<String, Object> properties = new HashMap<>();

            for (Field field : fields) {
                field.setAccessible(true);
                Object value = field.get(cryptoFactoryBean);
                properties.put(field.getName(), value);
            }

            // Registrar las propiedades en el registro
            for (Map.Entry<String, Object> entry : properties.entrySet()) {
                logger.info(entry.getKey() + ": " + entry.getValue());
            }
        } catch (Exception e) {
            logger.error("Error al obtener las propiedades de CryptoFactoryBean", e);
        }
    }
}
Luego, puedes usar esta función en tu aplicación para registrar las propiedades de una instancia de CryptoFactoryBean. Por ejemplo:

java
Copy code
CryptoFactoryBean cryptoFactoryBean = new CryptoFactoryBean();
// Configura las propiedades de CryptoFactoryBean según tus necesidades

CryptoFactoryBeanLogger.logCryptoFactoryBeanProperties(cryptoFactoryBean);
Asegúrate de configurar adecuadamente las propiedades de CryptoFactoryBean antes de llamar a la función logCryptoFactoryBeanProperties. Esta función obtendrá y registrará las propiedades y sus valores en el registro de la aplicación.

como se puede generar una clave de firma HMAC
ChatGPT
Para generar una clave de firma HMAC (Hash-based Message Authentication Code), puedes seguir estos pasos en Java utilizando la biblioteca Java Cryptography Architecture (JCA) y la clase javax.crypto.SecretKey. Asegúrate de que tengas las dependencias de seguridad adecuadas en tu proyecto.

java
Copy code
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

public class HMACKeyGenerator {

    public static SecretKey generateHMACKey() throws NoSuchAlgorithmException {
        // Elige el algoritmo HMAC que deseas utilizar (por ejemplo, "HmacSHA256")
        String hmacAlgorithm = "HmacSHA256";

        // Crea un generador de claves HMAC
        KeyGenerator keyGenerator = KeyGenerator.getInstance(hmacAlgorithm);

        // Genera una clave HMAC aleatoria
        SecretKey secretKey = keyGenerator.generateKey();

        return secretKey;
    }

    public static void main(String[] args) {
        try {
            SecretKey hmacKey = generateHMACKey();
            System.out.println("Clave HMAC generada: " + bytesToHex(hmacKey.getEncoded()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    // Función auxiliar para convertir bytes a una representación hexadecimal
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
En este código, la función generateHMACKey crea una clave HMAC aleatoria utilizando el algoritmo HMAC que elijas (en este caso, "HmacSHA256"). Puedes cambiar el valor de hmacAlgorithm para utilizar otro algoritmo HMAC si lo deseas.

La clave generada se almacena en un objeto SecretKey, y puedes obtener su representación en bytes utilizando hmacKey.getEncoded().

El método main muestra cómo usar generateHMACKey para generar una clave HMAC y la imprime en formato hexadecimal. Asegúrate de gestionar adecuadamente la clave generada y de almacenarla de forma segura en tu aplicación, ya que es esencial para la seguridad de las firmas HMAC.

por línea de comandos para almacenar en una jks
ChatGPT
Para almacenar una clave HMAC en un archivo de almacén de claves Java (JKS) utilizando la línea de comandos, puedes utilizar la herramienta keytool que viene incluida en la distribución de Java. Aquí tienes un ejemplo de cómo hacerlo:

Genera la clave HMAC y guárdala en un archivo binario (por ejemplo, hmac-key.bin):

bash
Copy code
# Genera la clave HMAC utilizando OpenSSL
openssl rand -out hmac-key.bin 32  # 32 bytes para HMAC-SHA256
Crea un archivo JKS y almacena la clave HMAC en él:

bash
Copy code
# Crea un archivo JKS (puedes cambiar 'mykeystore.jks' al nombre que desees)
keytool -genkey -alias hmac-key -keyalg HMAC -keysize 256 -keystore mykeystore.jks

# Importa la clave HMAC en el almacén de claves JKS
keytool -importkeystore -srckeystore hmac-key.bin -srcstoretype pkcs12 -destkeystore mykeystore.jks -deststoretype JKS
En este ejemplo:

keytool -genkey se utiliza para generar un par de claves (pública y privada) y almacenarlas en el almacén de claves JKS.
keytool -importkeystore se utiliza para importar la clave HMAC desde el archivo hmac-key.bin al almacén de claves JKS.
Durante el proceso, se te pedirá que establezcas una contraseña para el almacén de claves JKS y una contraseña para la clave HMAC. Asegúrate de recordar estas contraseñas, ya que las necesitarás para acceder a la clave HMAC en el futuro.

Verifica que la clave HMAC se haya almacenado correctamente en el almacén de claves JKS:

bash
Copy code
keytool -list -keystore mykeystore.jks
Se te pedirá la contraseña del almacén de claves y, después de ingresarla correctamente, verás una lista de las claves almacenadas, incluida la clave HMAC.

Ahora tienes la clave HMAC almacenada en un archivo JKS que puedes utilizar en tu aplicación Java para firmar y verificar datos utilizando HMAC. Asegúrate de proteger el almacén de claves JKS y las contraseñas adecuadamente, ya que son críticos para la seguridad de tus aplicaciones.

error de herramienta de claves: java.security.NoSuchAlgorithmException: HMAC KeyPairGenerator not available
ChatGPT
El error "java.security.NoSuchAlgorithmException: HMAC KeyPairGenerator not available" se produce porque keytool no admite la generación de pares de claves para algoritmos HMAC directamente, ya que HMAC es un algoritmo de firma basado en clave simétrica (no utiliza pares de claves públicas y privadas como RSA o DSA).

Para almacenar una clave HMAC en un archivo de almacén de claves Java (JKS), debes seguir los pasos que te mencioné en la respuesta anterior, pero sin intentar generar un par de claves. Simplemente, almacena la clave HMAC directamente en el almacén de claves JKS utilizando la herramienta keytool. Aquí tienes un resumen de los pasos correctos:

Genera la clave HMAC y guárdala en un archivo binario (por ejemplo, hmac-key.bin):

bash
Copy code
# Genera la clave HMAC utilizando OpenSSL
openssl rand -out hmac-key.bin 32  # 32 bytes para HMAC-SHA256
Crea un archivo JKS y almacena la clave HMAC en él:

bash
Copy code
# Crea un archivo JKS (puedes cambiar 'mykeystore.jks' al nombre que desees)
keytool -importkey -alias hmac-key -keypass <tu_contraseña> -file hmac-key.bin -keystore mykeystore.jks -storepass <tu_contraseña> -storetype JKS
En este paso, estás importando la clave HMAC (hmac-key.bin) directamente en el almacén de claves JKS (mykeystore.jks) sin intentar generar un par de claves.

Durante el proceso, se te pedirá que establezcas una contraseña para el almacén de claves JKS (-storepass) y una contraseña para la clave HMAC (-keypass). Asegúrate de recordar estas contraseñas, ya que las necesitarás para acceder a la clave HMAC en el futuro.

Verifica que la clave HMAC se haya almacenado correctamente en el almacén de claves JKS:

bash

https://1drv.ms/f/s!AgbNG_Edgh4apZ5O2Zqef-1745zPLg?e=XXR5H9
Copy code
keytool -list -keystore mykeystore.jks
Se te pedirá la contraseña del almacén de claves (-storepass) y, después de ingresarla correctamente, verás la clave HMAC en la lista de claves almacenadas.

De esta manera, podrás almacenar la clave HMAC en un almacén de claves JKS sin necesidad de generar un par de claves como lo harías para algoritmos de firma asimétrica como RSA o DSA. Asegúrate de proteger el almacén de claves JKS y las contraseñas adecuadamente.

se puede firmar un mensaje en SOAP con HMAC_SHA256  con una clave RSA 2048 
ChatGPT
No, no puedes firmar un mensaje SOAP con HMAC_SHA256 utilizando una clave RSA de 2048 bits. HMAC (Hash-based Message Authentication Code) y RSA (Rivest–Shamir–Adleman) son algoritmos de firma y autenticación completamente diferentes con propósitos distintos y no son intercambiables de manera directa.

HMAC_SHA256: HMAC es un algoritmo de autenticación de clave simétrica que utiliza una clave compartida para calcular un valor de autenticación basado en un hash (en este caso, SHA-256) del mensaje. HMAC se utiliza para verificar la integridad y autenticidad del mensaje.

RSA 2048: RSA, por otro lado, es un algoritmo de cifrado asimétrico que utiliza un par de claves (una pública y una privada) para cifrar y descifrar datos, así como para firmar y verificar firmas digitales. RSA se utiliza para garantizar la confidencialidad y autenticidad de los datos, y no se utiliza para calcular un HMAC.

Si deseas firmar un mensaje SOAP con HMAC_SHA256, necesitas una clave secreta compartida y no una clave RSA. El proceso general para firmar un mensaje SOAP con HMAC_SHA256 implica:

Calcular el HMAC_SHA256 del contenido del mensaje utilizando la clave secreta compartida.
Agregar el valor del HMAC_SHA256 calculado como una firma en la solicitud SOAP.
En el servidor, calcular el HMAC_SHA256 del contenido del mensaje recibido utilizando la misma clave secreta compartida y compararlo con la firma recibida para verificar la autenticidad e integridad del mensaje.
Si estás trabajando con claves RSA de 2048 bits, se utilizan para otros propósitos, como cifrado asimétrico o firma digital utilizando algoritmos como RSA_SHA256 (RSA con SHA-256), no HMAC_SHA256. Es importante entender la diferencia entre estos algoritmos y usar el adecuado para el propósito específico que deseas lograr en tu comunicación SOAP.


openssl pkcs12 -export -out hmac-key.pfx -inkey hmac-key.bin -in hmac-key.bin -name "HMAC Key"
# Puedes cambiar 'mypfxstore.pfx' al nombre que desees
keytool -importkeystore -srckeystore hmac-key.pfx -srcstoretype PKCS12 -destkeystore mypfxstore.pfx -deststoretype PKCS12


unable to load private key
140694361323440:error:0906D06C:PEM routines:PEM_read_bio:no start line:pem_lib.c:707:Expecting: ANY PRIVATE KEY


# Genera la clave HMAC utilizando OpenSSL
openssl rand -out hmac-key.bin 32  # 32 bytes para HMAC-SHA256

openssl pkcs12 -export -out hmac-key.pfx -inkey hmac-key.bin -in hmac-key.bin -name "HMAC Key" -passout pass:tu_nueva_contraseña -passin pass:tu_contraseña_actual

keytool -importkeystore -srckeystore hmac-key.pfx -srcstoretype PKCS12 -destkeystore mykeystore.jks -deststoretype JKS -srcstorepass tu_nueva_contraseña -deststorepass tu_nueva_contraseña



quiero saber 3 objetivos de una empresa española cuyo objetivo  es mejorar el bienestar de los pacientes a través de productos y tratamientos farmacológicos efectivos que persiguen aumentar su esperanza y calidad de vida. Se busca proveer a todas las personas de las mejores soluciones farmacológicas hospitalarias avanzadas y, para conseguirlo, se colabora con el sector hospitalario y con el sistema de salud pública para hacer los tratamientos accesibles y viables con los recursos de los que se dispone. La forma en la que la compañía quiere afrontar estos retos de cara al futuro tiene un denominador común: desarrollar fármacos cada vez más eficaces trabajando con rigor, fomentando la diversidad y la inclusión, la sostenibilidad y el compromiso con el medio ambiente

y para cada objetivo 3 okrs
**Objetivo 1: Desarrollar Fármacos Innovadores para Mejorar la Eficacia Terapéutica**

1. **KR1:** Investigar y desarrollar al menos tres nuevos compuestos farmacológicos con potencial terapéutico destacado en los próximos 12 meses.
2. **KR2:** Aumentar la tasa de éxito en ensayos clínicos en un 20% a través de mejoras en el diseño experimental y la gestión de datos.
3. **KR3:** Establecer colaboraciones estratégicas con al menos dos centros de investigación líderes en el ámbito de la salud para potenciar la innovación y el intercambio de conocimientos.

**Objetivo 2: Mejorar la Accesibilidad de los Tratamientos Farmacológicos**

1. **KR1:** Implementar un programa piloto en tres hospitales para optimizar la logística de distribución y reducir los tiempos de entrega de los productos farmacológicos.
2. **KR2:** Incrementar la disponibilidad de tratamientos asequibles en un 15% a través de acuerdos estratégicos con el sistema de salud pública.
3. **KR3:** Desarrollar al menos dos iniciativas de educación médica para profesionales de la salud con el objetivo de promover el uso efectivo de los tratamientos en pacientes.

**Objetivo 3: Impulsar la Sostenibilidad y el Compromiso Ambiental**

1. **KR1:** Reducir la huella de carbono en las operaciones de la empresa en un 10% mediante la implementación de prácticas ecoeficientes.
2. **KR2:** Integrar al menos dos criterios de sostenibilidad en el diseño de nuevos productos farmacológicos para garantizar la responsabilidad ambiental.
3. **KR3:** Fomentar la diversidad e inclusión en la investigación y desarrollo, aumentando la representación de grupos subrepresentados en un 20% en los equipos de proyecto clave.

necesito que me listes los objetivos y OKRS adaptados a un empleado en concreto, a un equipo y a una unidad de negocio.

**Empleado: Investigador Farmacéutico**

**Objetivo 1: Contribuir al Desarrollo de Nuevos Fármacos Innovadores**

1. **KR1:** Proponer al menos tres enfoques experimentales novedosos en los próximos seis meses para mejorar la eficacia terapéutica.
2. **KR2:** Participar activamente en al menos dos proyectos de investigación colaborativa con centros externos para potenciar la innovación.
3. **KR3:** Aumentar la tasa de éxito en ensayos clínicos en un 15% mediante la implementación de mejores prácticas en el diseño experimental.

**Objetivo 2: Optimizar la Eficiencia en el Desarrollo de Compuestos Farmacológicos**

1. **KR1:** Mejorar la eficiencia del proceso de investigación en un 10% mediante la identificación y aplicación de nuevas tecnologías y métodos.
2. **KR2:** Colaborar con el equipo de logística para reducir los tiempos de entrega de muestras en un 20% durante los ensayos clínicos.
3. **KR3:** Participar en al menos dos programas de formación para mantenerse actualizado sobre las últimas tendencias y avances en investigación farmacológica.

**Objetivo 3: Promover la Cultura de Diversidad e Inclusión en el Equipo de Investigación**

1. **KR1:** Participar en al menos una iniciativa de diversidad e inclusión dentro del departamento en el próximo trimestre.
2. **KR2:** Colaborar con Recursos Humanos para implementar medidas que fomenten la igualdad de oportunidades en el equipo.
3. **KR3:** Actuar como mentor de un nuevo miembro del equipo, promoviendo un ambiente de trabajo inclusivo y colaborativo.

---

**Equipo: Equipo de Distribución y Logística**

**Objetivo 1: Optimizar la Cadena de Suministro para Reducir los Tiempos de Entrega**

1. **KR1:** Implementar un sistema de gestión de inventario más eficiente, reduciendo los tiempos de preparación de pedidos en un 15%.
2. **KR2:** Colaborar con el equipo de investigación para anticipar la demanda y evitar posibles interrupciones en la cadena de suministro.
3. **KR3:** Mejorar la precisión del seguimiento de envíos en un 20% para proporcionar información en tiempo real a los clientes.

**Objetivo 2: Incrementar la Sostenibilidad en las Operaciones Logísticas**

1. **KR1:** Introducir prácticas de embalaje sostenible que reduzcan el desperdicio de materiales en un 10%.
2. **KR2:** Colaborar con proveedores de transporte con certificación ambiental para reducir la huella de carbono en los envíos.
3. **KR3:** Desarrollar un programa de concienciación sobre sostenibilidad entre los miembros del equipo.

**Objetivo 3: Mejorar la Colaboración Interdepartamental para una Distribución Eficiente**

1. **KR1:** Establecer reuniones regulares con el equipo de investigación para comprender mejor las necesidades de distribución anticipadas.
2. **KR2:** Implementar un sistema de comunicación más efectivo entre el equipo de logística y otros departamentos para resolver problemas de manera más rápida.
3. **KR3:** Reducir en un 15% los errores en la preparación de pedidos a través de un mayor intercambio de información con el equipo de calidad.

---

**Unidad de Negocio: Departamento de Relaciones con el Sistema de Salud Pública**

**Objetivo 1: Fortalecer la Colaboración con el Sistema de Salud Pública para Garantizar el Acceso a Tratamientos Efectivos**

1. **KR1:** Establecer acuerdos estratégicos con al menos tres hospitales clave para asegurar la disponibilidad de productos farmacológicos.
2. **KR2:** Implementar un programa de formación para profesionales de la salud en colaboración con el equipo de investigación para promover el uso efectivo de los tratamientos.
3. **KR3:** Medir y mejorar la satisfacción del cliente (hospitales y profesionales de la salud) en un 15% en los próximos seis meses.

**Objetivo 2: Alinear Estrategias de Desarrollo con las Necesidades del Sistema de Salud Pública**

1. **KR1:** Colaborar con el equipo de investigación para desarrollar productos farmacológicos que aborden las necesidades específicas del sistema de salud pública.
2. **KR2:** Participar en al menos dos eventos del sector de la salud para comprender las tendencias emergentes y adaptar las estrategias de desarrollo en consecuencia.
3. **KR3:** Establecer una plataforma en línea para facilitar la comunicación y el intercambio de información entre la empresa y el sistema de salud pública.

**Objetivo 3: Promover la Sostenibilidad y el Compromiso Ambiental en la Unidad de Negocio**

1. **KR1:** Implementar prácticas sostenibles en la gestión diaria de la unidad, reduciendo el consumo de recursos en un 10%.
2. **KR2:** Desarrollar un programa de responsabilidad social corporativa centrado en la salud y el medio ambiente, con al menos dos iniciativas implementadas en el próximo año.
3. **KR3:** Aumentar la transparencia en las prácticas de sostenibilidad, proporcionando informes regulares sobre el impacto ambiental de las operaciones del departamento.

unidad de negocio me lo puedes cambiar y ponerme como unidad de negocio la de "Ventas farmaceuticas"

**Unidad de Negocio: Departamento de Ventas Farmacéuticas**

**Objetivo 1: Impulsar las Ventas de Productos Farmacológicos en el Mercado**

1. **KR1:** Aumentar las ventas trimestrales en un 15% mediante la identificación y aprovechamiento de oportunidades de mercado.
2. **KR2:** Desarrollar y ejecutar al menos dos estrategias de marketing efectivas para promover productos clave y aumentar la demanda.
3. **KR3:** Establecer relaciones comerciales sólidas con al menos tres nuevos clientes estratégicos en el próximo año.

**Objetivo 2: Mejorar la Eficiencia en la Gestión de Clientes y Pedidos**



1. **KR1:** Implementar un sistema de gestión de relaciones con el cliente (CRM) mejorado para optimizar el seguimiento y la comunicación con clientes.
2. **KR2:** Reducir los tiempos de procesamiento de pedidos en un 20% a través de la implementación de procesos más eficientes.
3. **KR3:** Incrementar la satisfacción del cliente en un 10% mediante una atención personalizada y rápida resolución de problemas.

**Objetivo 3: Expandir la Presencia en Nuevos Mercados y Segmentos**

1. **KR1:** Identificar y analizar al menos dos nuevos mercados o segmentos de clientes potenciales para la expansión.
2. **KR2:** Establecer al menos una asociación estratégica con distribuidores locales para mejorar la presencia en un mercado objetivo.
3. **KR3:** Incrementar la cuota de mercado en productos específicos en al menos dos regiones geográficas clave en los próximos 12 meses

4. Private Sub Application_NewMailEx(ByVal EntryIDCollection As String)
    On Error Resume Next
    
    Dim objNS As Outlook.NameSpace
    Dim objMail As Outlook.MailItem
    Dim objFolder As Outlook.Folder
    Dim strScriptPath As String
    
    ' Ruta al script Python
    strScriptPath = "C:\Ruta\Al\Script.py"
    
    ' Obtener el objeto Namespace
    Set objNS = Application.GetNamespace("MAPI")
    
    ' Recorrer las entradas de correo electrónico
    For Each EntryID In Split(EntryIDCollection, ",")
        ' Obtener el objeto de correo
        Set objMail = objNS.GetItemFromID(EntryID)
        
        ' Verificar si el correo cumple con ciertas condiciones (puedes ajustar esto)
        If objMail.Subject Like "*PalabraClave*" Then
            ' Ejecutar el script Python
            Call Shell("python " & strScriptPath, vbNormalFocus)
        End If
    Next
    
    ' Liberar objetos
    Set objMail = Nothing
    Set objNS = Nothing
End Sub

