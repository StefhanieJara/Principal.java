
/**Nombre: Stefhanie Milagros Jaramillo Huaman


 ***/


import java.io.*;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Asimetrica {
    public void generarClaves(String nombreClavePrivada, String nombreClavePublica) {
        try {
            // Generamos las claves RSA con 2048 bits de longitud
            RSAKeyPairGenerator generadorClaves = new RSAKeyPairGenerator();
            //Se crean los parametros para la generación de claves RSA, para ello se incluye la base de la clave, numero de bits y veces de repeticion para quesea mas fuerte
            RSAKeyGenerationParameters parametros = new RSAKeyGenerationParameters(BigInteger.valueOf(3), new SecureRandom(), 2048, 10);
            //iniciamos el generador de claves con los parametros especificados antes:
            generadorClaves.init(parametros);
            //generamos el par de claves RSA utilizando el generador de claves inicializado
            AsymmetricCipherKeyPair parClaves = generadorClaves.generateKeyPair();

            //Guardar en formato PEM usando la clase dada anteriormente
            GuardarFormatoPEM FPEM = new GuardarFormatoPEM();
            FPEM.guardarClavesPEM(parClaves.getPublic(), parClaves.getPrivate());

            // Obtenemos la clave privada y la guardamos en un archivo
            RSAPrivateCrtKeyParameters clavePrivada = (RSAPrivateCrtKeyParameters) parClaves.getPrivate();

            //Se crea un objeto PrintWriter para escribir la clave privada en un archivo.
            PrintWriter ficheroPrivada = new PrintWriter(new FileWriter(nombreClavePrivada));
            ficheroPrivada.println(new String(Hex.encode(clavePrivada.getModulus().toByteArray()))); // Módulo en hexadecimal
            ficheroPrivada.print(new String(Hex.encode(clavePrivada.getExponent().toByteArray()))); // Exponente en hexadecimal
            ficheroPrivada.close();

            // Obtenemos la clave pública y la guardamos en otro archivo
            RSAKeyParameters clavePublica = (RSAKeyParameters) parClaves.getPublic();
            //Se crea un objeto PrintWriter para escribir la clave publica
            PrintWriter ficheroPublica = new PrintWriter(new FileWriter(nombreClavePublica));
            ficheroPublica.println(new String(Hex.encode(clavePublica.getModulus().toByteArray()))); // Módulo en hexadecimal
            ficheroPublica.print(new String(Hex.encode(clavePublica.getExponent().toByteArray()))); // Exponente en hexadecimal
            ficheroPublica.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void cifrar(String tipo, String ficheroClave, String ficheroEntrada, String ficheroSalida) throws Exception {
        // Leemos la clave
        BufferedReader lectorClave = new BufferedReader(new FileReader(ficheroClave));
        BigInteger modulo = new BigInteger(Hex.decode(lectorClave.readLine()));
        BigInteger exponente = new BigInteger(Hex.decode(lectorClave.readLine()));
        RSAKeyParameters parametros = new RSAKeyParameters(tipo.equals("privada"), modulo, exponente);

        // Creamos el cifrador RSA con PKCS1Padding
        AsymmetricBlockCipher cifrador = new PKCS1Encoding(new RSAEngine());
        cifrador.init(true, parametros);

        // Abrimos los ficheros de entrada y salida
        FileInputStream fis = new FileInputStream(ficheroEntrada);
        FileOutputStream fos = new FileOutputStream(ficheroSalida);

        // Leemos el fichero de entrada en bloques de tamaño máximo 240 bytes
        byte[] buffer = new byte[240];
        byte[] datosCifrados;
        int bytesLeidos;
        while ((bytesLeidos = fis.read(buffer)) > 0) {
            // Ciframos cada fragmento de forma independiente
            byte[] datosCifradosFragmento = cifrador.processBlock(buffer, 0, bytesLeidos);
            fos.write(datosCifradosFragmento);
        }

        // Cerramos los ficheros
        fis.close();
        fos.close();
    }

    public void descifrar(String tipo, String ficheroClave, String ficheroCifrado, String ficheroDescifrado)
            throws IOException, InvalidCipherTextException {
        //Se crea un objeto BufferedReader que leerá el archivo de la clave privada o pública.
        BufferedReader lectorClave = new BufferedReader(new FileReader(ficheroClave));
        //Se lee el primer registro del archivo de clave que contiene el módulo del cifrado RSA.
        BigInteger modulo = new BigInteger(Hex.decode(lectorClave.readLine()));
        //Se lee el segundo registro del archivo de clave que contiene el exponente del cifrado RSA.
        BigInteger exponente = new BigInteger(Hex.decode(lectorClave.readLine()));
        //Se crean los parámetros de la clave RSA utilizando el tipo de clave (privada o pública), el módulo y el exponente.
        RSAKeyParameters parametros = new RSAKeyParameters(tipo.equals("privada"), modulo, exponente);
        //Se crea un objeto AsymmetricBlockCipher que utiliza una implementación de RSA y se le pasa como parámetro el cifrador RSA.
        AsymmetricBlockCipher descifrador = new PKCS1Encoding(new RSAEngine());
        //Se inicializa el cifrador RSA para descifrar los datos y se le pasan los parámetros de la clave.
        descifrador.init(false, parametros);
        //Se crea un objeto FileInputStream para leer el archivo cifrado.
        FileInputStream fis = new FileInputStream(ficheroCifrado);
        //Se crea un objeto FileOutputStream para escribir el archivo descifrado.
        FileOutputStream fos = new FileOutputStream(ficheroDescifrado);
        //Se crea un objeto BufferedInputStream para leer el archivo cifrado.
        BufferedInputStream bis = new BufferedInputStream(fis);
        //Se crea un objeto BufferedInputStream para leer el archivo cifrado.
        BufferedOutputStream bos = new BufferedOutputStream(fos);
        //Se crea un buffer de bytes con el tamaño del bloque de entrada del cifrador RSA.
        byte[] buffer = new byte[descifrador.getInputBlockSize()];
        int leidos = 0;
        //Se inicia un bucle que lee datos del archivo cifrado en bloques del tamaño del buffer y descifra cada bloque utilizando el cifrador RSA.
        while ((leidos = bis.read(buffer)) > 0) {
            byte[] datosDescifrados = descifrador.processBlock(buffer, 0, leidos);
            bos.write(datosDescifrados, 0, datosDescifrados.length);
        }

        bis.close();
        bos.close();
    }

    public void firmar(String ficheroClave, String ficheroEntrada, String ficheroSalida)
            throws IOException, InvalidCipherTextException, NoSuchAlgorithmException {
        // Para el resumen creamos un objeto
        Digest resumen = new SHA3Digest();

        // Se lee la clave privada del fichero
        BufferedReader lectorClave = new BufferedReader(new FileReader(ficheroClave));
        BigInteger modulo = new BigInteger(Hex.decode(lectorClave.readLine()));
        BigInteger exponente = new BigInteger(Hex.decode(lectorClave.readLine()));
        RSAKeyParameters parametros = new RSAKeyParameters(true, modulo, exponente);


        //Para cifrar con RSA se crea un objeto
        AsymmetricBlockCipher cifrador = new PKCS1Encoding(new RSAEngine());
        cifrador.init(true, parametros);

        // Para leer un fichero de entrada se crea un objeto
        FileInputStream fisEntrada = new FileInputStream(ficheroEntrada);
        BufferedInputStream bisEntrada = new BufferedInputStream(fisEntrada);

        // Se crea un objeto para escribir el fichero intermedio con el resumen
        FileOutputStream fosResumen = new FileOutputStream(ficheroSalida + ".resumen");
        BufferedOutputStream bosResumen = new BufferedOutputStream(fosResumen);

        // Para escribir la firma creamos un objeto
        FileOutputStream fosFirma = new FileOutputStream(ficheroSalida);
        BufferedOutputStream bosFirma = new BufferedOutputStream(fosFirma);

        // Se procesa los bloques del archivo
        byte[] buffer = new byte[resumen.getDigestSize()];
        int leidos = 0;
        while ((leidos = bisEntrada.read(buffer)) > 0) {
            resumen.update(buffer, 0, leidos);
            bosResumen.write(buffer, 0, leidos);
        }

        // Generamos el resumen final
        byte[] resumenFinal = new byte[resumen.getDigestSize()];
        resumen.doFinal(resumenFinal, 0);

        // Se cifra el resumen final con RSA y escribir la firma
        byte[] firma = cifrador.processBlock(resumenFinal, 0, resumenFinal.length);
        bosFirma.write(firma);

        // Cerramos todos los recursos
        bisEntrada.close();
        bosResumen.close();
        bosFirma.close();
    }

    public boolean verificarFirma(String ficheroClavePublica, String ficheroMensaje, String ficheroFirma)
            throws IOException, InvalidCipherTextException {
        // Leemos la clave pública
        BufferedReader lectorClave = new BufferedReader(new FileReader(ficheroClavePublica));
        BigInteger modulo = new BigInteger(Hex.decode(lectorClave.readLine()));
        BigInteger exponente = new BigInteger(Hex.decode(lectorClave.readLine()));
        RSAKeyParameters parametros = new RSAKeyParameters(false, modulo, exponente);

        // Desciframos el fichero de firma con clave pública
        AsymmetricBlockCipher descifrador = new PKCS1Encoding(new RSAEngine());
        descifrador.init(false, parametros);
        FileInputStream fisFirmaCifrada = new FileInputStream(ficheroFirma);
        FileOutputStream fosFirmaDescifrada = new FileOutputStream("firmaDescifrada.txt");
        BufferedInputStream bisFirmaCifrada = new BufferedInputStream(fisFirmaCifrada);
        BufferedOutputStream bosFirmaDescifrada = new BufferedOutputStream(fosFirmaDescifrada);
        byte[] bufferFirmaCifrada = new byte[descifrador.getInputBlockSize()];
        int leidosFirmaCifrada = 0;
        while ((leidosFirmaCifrada = bisFirmaCifrada.read(bufferFirmaCifrada)) > 0) {
            byte[] datosDescifrados = descifrador.processBlock(bufferFirmaCifrada, 0, leidosFirmaCifrada);
            bosFirmaDescifrada.write(datosDescifrados, 0, datosDescifrados.length);
        }
        bisFirmaCifrada.close();
        bosFirmaDescifrada.close();

        // generamos el resumen del mensaje
        Digest resumen = new SHA3Digest();
        FileInputStream fisMensaje = new FileInputStream(ficheroMensaje);
        BufferedInputStream bisMensaje = new BufferedInputStream(fisMensaje);
        byte[] bufferMensaje = new byte[resumen.getDigestSize()];
        int leidosMensaje = 0;
        while ((leidosMensaje = bisMensaje.read(bufferMensaje)) > 0) {
            resumen.update(bufferMensaje, 0, leidosMensaje);
        }
        bisMensaje.close();
        byte[] resumenMensaje = new byte[resumen.getDigestSize()];
        resumen.doFinal(resumenMensaje, 0);

        // Leeemos el fichero de firma descifrada
        FileInputStream fisFirmaDescifrada = new FileInputStream("firmaDescifrada.txt");
        BufferedInputStream bisFirmaDescifrada = new BufferedInputStream(fisFirmaDescifrada);
        byte[] firmaDescifrada = new byte[resumen.getDigestSize()];
        int leidosFirmaDescifrada = 0;
        while ((leidosFirmaDescifrada = bisFirmaDescifrada.read(firmaDescifrada)) > 0) {
            // No hace nada, sólo lee el fichero y lo almacena en la variable firmaDescifrada
        }
        bisFirmaDescifrada.close();

        // Se verifica que los resúmenes coinciden
        boolean resultado = Arrays.equals(firmaDescifrada, resumenMensaje);

        // Se elimina el fichero  de la firma descifrada
        File ficheroDescifrado = new File("firmaDescifrada.txt");
        ficheroDescifrado.delete();

        return resultado;
    }





}

