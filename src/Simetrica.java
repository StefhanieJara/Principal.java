
/**Nombre: Stefhanie Milagros Jaramillo Huaman
 Horario: V10V11

 ***/


import java.io.*;
import java.security.SecureRandom;

import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;
public class Simetrica {
    public void generarClave(String nombreArchivo) throws IOException {
        //Se crea el generador de claves
        CipherKeyGenerator generador = new CipherKeyGenerator();
        //SecureRandom para generar numeros aleatorios.
        SecureRandom aleatoriedad = new SecureRandom();
        int tamanoClave = 256;
        // Se crean los parámetros de generación de clave, utilizando el objeto SecureRandom y el tamaño de clave definido anteriormente.
        KeyGenerationParameters parametros = new KeyGenerationParameters(aleatoriedad, tamanoClave);
        //Se inicializa el generador
        generador.init(parametros);
        //Se genera la clave aleatoria en formato de bytes.
        byte[] claveBytes = generador.generateKey();
        //Se convierte la clave aleatoria en formato hexadecimal utilizando la clase hex
        String claveHex = new String(Hex.encode(claveBytes));
        //Se convierte la clave aleatoria en formato hexadecimal utilizando la clase
        String extension = ".txt";
        String nombreCompleto = nombreArchivo + extension;
        FileOutputStream archivo = new FileOutputStream(nombreCompleto);
        // Se escribe la clave en formato hexadecimal en el archivo.
        archivo.write(claveHex.getBytes());
        archivo.close();
    }

    public void cifrar(String archivoEntrada, String archivoSalida, String archivoClave) throws IOException, InvalidCipherTextException {
        // Leer el archivo clave y decodificarlo de hexadecimal a binario
        BufferedReader lectorClave = new BufferedReader(new FileReader(archivoClave));
        byte[] clave = Hex.decode(lectorClave.readLine());
        lectorClave.close();

        // Generar los parámetros y cargar la clave
        KeyParameter params = new KeyParameter(clave);

        // Crear el motor de cifrado con CBC, TwoFish y PKCS7Padding
        BlockCipher engine = new TwofishEngine();
        BufferedBlockCipher cifrador = new PaddedBufferedBlockCipher(new CBCBlockCipher(engine), new PKCS7Padding());

        // Iniciar el motor de cifrado con los parámetros
        cifrador.init(true, params);


        // Crear flujos de entrada/salida para los archivos
        BufferedInputStream entrada = new BufferedInputStream(new FileInputStream(archivoEntrada));
        BufferedOutputStream salida = new BufferedOutputStream(new FileOutputStream(archivoSalida));

        // Crear arrays de bytes para los datos leídos y cifrados
        byte[] datosLeidos = new byte[cifrador.getBlockSize()];
        byte[] datosCifrados = new byte[cifrador.getOutputSize(datosLeidos.length)];

        // Bucle de lectura, cifrado y escritura de bloques de datos
        int numBytesLeidos;
        while ((numBytesLeidos = entrada.read(datosLeidos)) > 0) {
            int numBytesCifrados = cifrador.processBytes(datosLeidos, 0, numBytesLeidos, datosCifrados, 0);
            salida.write(datosCifrados, 0, numBytesCifrados);
        }

        // Cifrar el último bloque y escribirlo
        int numBytesCifrados = cifrador.doFinal(datosCifrados, 0);
        salida.write(datosCifrados, 0, numBytesCifrados);

        // Cerrar los flujos de entrada/salida
        entrada.close();
        salida.close();
    }

    public void descifrar(String archivoCifrado, String archivoClave, String archivoDescifrado) throws IOException, DataLengthException, IllegalStateException, InvalidCipherTextException {

        // Leemos la clave en hexadecimal desde el archivo
        BufferedReader br = new BufferedReader(new FileReader(archivoClave));
        String hex = br.readLine();
        br.close();

        // Convertimos la clave de hexadecimal a binario
        byte[] clave = Hex.decode(hex);

        // Generamos los parámetros de la clave y creamos el motor de cifrado
        KeyParameter params = new KeyParameter(clave);
        PaddedBufferedBlockCipher cifrador = new PaddedBufferedBlockCipher(
                new CBCBlockCipher(new TwofishEngine()), new PKCS7Padding());

        // Iniciamos el motor de cifrado con los parámetros de la clave
        cifrador.init(false, params);

        // Creamos flujos de entrada y salida de ficheros
        BufferedInputStream in = new BufferedInputStream(new FileInputStream(archivoCifrado));
        BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(archivoDescifrado));

        // Creamos arrays de bytes para los datos leídos y descifrados
        byte[] bufferEntrada = new byte[cifrador.getBlockSize()];
        byte[] bufferSalida = new byte[cifrador.getOutputSize(bufferEntrada.length)];

        // Bucle de lectura, descifrado y escritura de bloques de datos
        int bytesLeidos;
        while ((bytesLeidos = in.read(bufferEntrada)) != -1) {
            int bytesProcesados = cifrador.processBytes(bufferEntrada, 0, bytesLeidos, bufferSalida, 0);
            out.write(bufferSalida, 0, bytesProcesados);
        }
        int bytesProcesados = cifrador.doFinal(bufferSalida, 0);
        out.write(bufferSalida, 0, bytesProcesados);

        // Cerramos los flujos de entrada y salida
        in.close();
        out.close();
    }





}

