package cifraado;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.spec.KeySpec;
import java.util.*;
import java.io.*;

public class CrearClaves extends Constantes {

    public static void main(String[] args) throws Exception {
        // Generamos las claves publica/privada
        SecureRandom sr = new SecureRandom();
        sr.setSeed(new Date().getTime());
        System.out.println("Generando claves...");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(TAMANO_CLAVE_RSA, sr);
        KeyPair par_claves = kpg.generateKeyPair();
        System.out.println("Claves generadas");

        // Generamos el fichero de la clave pública
        System.out.print("Indique fichero para la clave pública:");
        BufferedReader teclado = new BufferedReader(new InputStreamReader(System.in));
        String fichero_publica = teclado.readLine();
        FileOutputStream fos = new FileOutputStream(fichero_publica);
        fos.write(par_claves.getPublic().getEncoded());
        fos.close();
        System.out.println("Fichero con clave pública generado");

        // Generamos el fichero de clave privada cifrada
        System.out.print("Indique fichero para la clave privada cifrada:");
        String fichero_privada = teclado.readLine();
        System.out.print("La clave privada debe estar encriptada, indique password con la que encriptarla:");
        char[] password = teclado.readLine().toCharArray();

        // Encriptamos con AES
        byte[] salt = new byte[TAMANO_SALT_BYTES];
        sr.nextBytes(salt);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password, salt, ITERACIONES_PBE, TAMANO_CLAVE_SESION * 8);
        SecretKey clave_secreta_pbe = factory.generateSecret(spec);

        Cipher cifrador_pbe = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cifrador_pbe.init(Cipher.ENCRYPT_MODE, clave_secreta_pbe);
        byte[] clave_privada_cifrada = cifrador_pbe.doFinal(par_claves.getPrivate().getEncoded());

        // Generamos el fichero .crypto con los datos encriptados
        String fichero_crypto = fichero_privada + ".crypto";
        fos = new FileOutputStream(fichero_crypto);
        fos.write(salt);
        fos.write(clave_privada_cifrada);
        fos.close();
        System.out.println("Fichero con clave privada cifrada generado: " + fichero_crypto);

        // Movemos el fichero a la ubicación deseada
        String ruta_destino = "/Users/rafagonzalezmartin/NetBeansProjects/Cifrado/src/firmafichero/" + fichero_crypto;
        File archivo_crypto = new File(fichero_crypto);
        File destino = new File(ruta_destino);
        if (archivo_crypto.renameTo(destino)) {
            System.out.println("Fichero movido correctamente a: " + ruta_destino);
        } else {
            System.out.println("No se pudo mover el fichero a la ubicación deseada.");
        }
    }
}
