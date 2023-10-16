/**Fichero: Principal.java
 * Clase para comprobar el funcionamiento de las otras clases del paquete.
 * Asignatura: SEG
 * @author Profesores de la asignatura
 * @version 1.0
 */

/**Nombre: Stefhanie Milagros Jaramillo Huaman
 Horario: V10V11

 ***/

import org.bouncycastle.crypto.InvalidCipherTextException;

import javax.sound.midi.Soundbank;
import java.io.*;
import java.util.Scanner;

public class Principal {

    public static void main (String [ ] args) throws Exception {
        int menu1;
        int menu2;
        Scanner sc = new Scanner(System.in);
        /* completar declaracion de variables e instanciación de objetos */
        Simetrica simetrica = new Simetrica();
        Asimetrica asimetrica = new Asimetrica();

        do {
            System.out.println("¿Qué tipo de criptografía desea utilizar?");
            System.out.println("1. Simétrico.");
            System.out.println("2. Asimétrico.");
            System.out.println("3. Salir.");
            menu1 = sc.nextInt();

            switch(menu1){
                case 1:
                    do{
                        System.out.println("Elija una opción para CRIPTOGRAFIA SIMÉTRICA:");
                        System.out.println("0. Volver al menú anterior.");
                        System.out.println("1. Generar clave.");
                        System.out.println("2. Cifrado.");
                        System.out.println("3. Descifrado.");
                        menu2 = sc.nextInt();

                        switch(menu2){
                            case 1:
                                Scanner scanner5 = new Scanner(System.in);

                                System.out.println("Escriba el nombre que quiera que el archivo de claves para encriptar posea: ");
                                String nombreArchivoClaves= scanner5.nextLine();
                                simetrica.generarClave(nombreArchivoClaves);
                                System.out.println("Su archivo de claves a sido generado");
                                break;
                            case 2:
                                Scanner scanner6 = new Scanner(System.in);

                                System.out.println("Escriba el nombre del archivo que contiene la clave con su extencion: ");
                                String nombreClave= scanner6.nextLine();
                                System.out.println("Escriba el nombre del archivo que será cifrado con su extension: ");
                                String nombreArchivoCifrar= scanner6.nextLine();
                                System.out.println("Escriba el nombre que quiera que el archivo cifrado posea con su extensión: ");
                                String nombreArchivoYaCifrado = scanner6.nextLine();

                                try {
                                    simetrica.cifrar(nombreArchivoCifrar, nombreArchivoYaCifrado, nombreClave);
                                } catch (IOException | InvalidCipherTextException e) {
                                    e.printStackTrace();
                                }
                                break;
                            case 3:
                                Scanner scanner7 = new Scanner(System.in);

                                System.out.println("Escriba el nombre del archvio que contiene la clave con su extensión: ");
                                String nombreClave2 = scanner7.nextLine();
                                System.out.println("Escriba el nombre del archivo que será decifrado con su extension: ");
                                String nombreCifrado =scanner7.nextLine();
                                System.out.println("Escriba el nombre que quiera que el archivo decifrado posea con su extensión: ");
                                String nombreFinal= scanner7.nextLine();
                                try {
                                    simetrica.descifrar(nombreCifrado, nombreClave2, nombreFinal);
                                } catch (IOException | InvalidCipherTextException e) {
                                    e.printStackTrace();
                                }


                                break;
                        }
                    } while(menu2 != 0);
                    break;
                case 2:
                    do{
                        System.out.println("Elija una opción para CRIPTOGRAFIA ASIMÉTRICA:");
                        System.out.println("0. Volver al menú anterior.");
                        System.out.println("1. Generar clave.");
                        System.out.println("2. Cifrado.");
                        System.out.println("3. Descifrado.");
                        System.out.println("4. Firmar digitalmente.");
                        System.out.println("5. Verificar firma digital.");
                        menu2 = sc.nextInt();

                        switch(menu2){
                            case 1:
                                Scanner scanner1 = new Scanner(System.in);
                                System.out.println("Escriba el nombre que quiera que el archivo de la clave publica posea con su extensión: ");
                                String nombreClavePublica= scanner1.nextLine();

                                System.out.println("Escriba el nombre que quiera que el archivo de la clave privada posea con su extensión: ");
                                String nombreClavePrivada= scanner1.nextLine();
                                asimetrica.generarClaves(nombreClavePrivada, nombreClavePublica);
                                break;
                            case 2:
                                Scanner scanner = new Scanner(System.in);
                                System.out.println("Escriba el tipo de clave que va a utilizar (publica o privada): ");
                                String nombreTipoClave = scanner.nextLine();
                                System.out.println("Escriba el nombre del archivo donde se encuentra la clave con su extensión: ");
                                String nombreClaveAsimetrico = scanner.nextLine();
                                System.out.println("Escriba el nombre del archivo a cifrar con su extensión: ");
                                String nombreLimpioAsimetrico = scanner.nextLine();
                                System.out.println("Escriba el nombre que desea que el fichero cifrado tenga con su extensión: ");
                                String nombreCifradoAsimetrico = scanner.nextLine();

                                asimetrica.cifrar(nombreTipoClave, nombreClaveAsimetrico, nombreLimpioAsimetrico, nombreCifradoAsimetrico);
                                break;
                            case 3:
                                Scanner scanner2 = new Scanner(System.in);
                                System.out.println("Escriba el tipo de clave que va a utilizar (publica o privada): ");
                                String nombreTipoClave2 = scanner2.nextLine();
                                System.out.println("Escriba el nombre del archivo donde se encuentra la clave con su extensión: ");
                                String nombreClaveDesencriptar = scanner2.nextLine();
                                System.out.println("Escriba el nombre del archivo cifrado con su extensión: ");
                                String nombrecifradoAsimetrico = scanner2.nextLine();
                                System.out.println("Escriba el nombre que desea que el fichero descifrado tenga con su extensión: ");
                                String nombredescifradoAsimetrico = scanner2.nextLine();

                                try {
                                    asimetrica.descifrar(nombreTipoClave2, nombreClaveDesencriptar, nombrecifradoAsimetrico, nombredescifradoAsimetrico);
                                } catch (Exception e) {
                                    throw new RuntimeException(e);
                                }
                                break;
                            case 4:
                                Scanner scanner3 = new Scanner(System.in);
                                System.out.println("Escriba el nombre donde se encuentra el archivo de la clave privada con la que va a cifrar la firma con su extensión: ");
                                String NombreCifrarPrivada = scanner3.nextLine();
                                System.out.println("Escriba el nombre del archivo con el mensaje en claro que se quiere enviar con su extensión: ");
                                String NombreArchivoClaro = scanner3.nextLine();
                                System.out.println("Escriba el nombre que desea que el archivo de la firma tenga con su extensión: ");
                                String NombreArchivoFirma = scanner3.nextLine();
                                asimetrica.firmar(NombreCifrarPrivada, NombreArchivoClaro, NombreArchivoFirma);
                                break;
                            case 5:
                                Scanner scanner4 = new Scanner(System.in);
                                System.out.println("Escribe el nombre del archivo donde se encuentra la clave publica con su extensión: ");
                                String NombreClavePublica = scanner4.nextLine();
                                System.out.println("Escriba el nombre del archivo con el mensaje en claro que se quiere enviar con su extensión: ");
                                String NombreArchivoLimpio = scanner4.nextLine();
                                System.out.println("Esriba el nombre del archivo donde se encuentra la firma con su extensión: ");
                                String NombreArchivoFirma1 = scanner4.nextLine();
                                Boolean confirmacion = asimetrica.verificarFirma(NombreClavePublica,NombreArchivoLimpio,NombreArchivoFirma1);
                                if (confirmacion==true){
                                    System.out.println("Se a verificado que la firma es la correcta.");
                                }else{
                                    System.out.println("No es la firma correcta.");
                                }
                                break;
                        }
                    } while(menu2 != 0);
                    break;
            }
        } while(menu1 != 3);
        sc.close();
    }
}