# Cifrado con PBEWithSHAAndTwofish-CBC y RSA
Este programa consiste en indicarle la ruta al fichero que queremos encriptar, esta práctca es utilizada para no filtrar ninguna información para las personas agenas.

# ¿Qué es PBEWithSHAAndTwofish-CBC?
PBEWithSHAAndTwofish-CBC es un tipo de algoritmo de encriptación que se utiliza para proteger la información mediante el uso de una contraseña. En este caso, se emplea el algoritmo de cifrado Twofish para asegurar los datos y la función hash SHA para añadir una capa adicional de seguridad. En resumen, este método ayuda a proteger la información utilizando una contraseña y combinando diferentes técnicas de encriptación para garantizar la seguridad de los datos.

# ¿Qué es RSA?
RSA es un algoritmo de encriptación desigual, ampliamente utilizado en la seguridad de la información.

# ¿En qué consiste PBEWithSHAAndTwofish-CBC?
Consiste en un algoritmo de cifrado híbrido que combina las funciones de hash SHA con el cifrado Twofish en modo de operación CBC. Se utiliza para proteger la confidencialidad de datos sensibles en aplicaciones Java. 

# ¿En qué consiste RSA?
RSA es un sistema de criptografía utilizado para proteger información confidencial en internet. Funciona mediante la generación de un par de claves: una clave pública y una clave privada. La clave pública se utiliza para cifrar los datos y la clave privada se utiliza para descifrarlos. Esto significa que cualquier persona puede cifrar datos utilizando la clave pública, pero solo la persona que posee la clave privada correspondiente puede descifrarlos. RSA es muy importante para la seguridad en línea, ya que garantiza que solo las personas autorizadas puedan acceder a información sensible, como contraseñas o datos bancarios.

## Comenzando 🚀
Lo primero de todo vamos a guardarnos en la carpeta ficheroPruebas, el fichero que queremos encriptar con PBEWithSHAAndTwofish-CBC.
![](https://github.com/rafael2347/CifradosJava/blob/main/Captura%20de%20pantalla%202024-03-08%20a%20las%2010.12.30.png)<br>
Lo segundo vamos a lanzar nuestro programa, nos pedirá la dirección del fichero que queremos encriptar.
![](https://github.com/rafael2347/CifradosJava/blob/main/Captura%20de%20pantalla%202024-03-08%20a%20las%2010.17.47.png)<br>
Lo tercero nos pedirá la dirección del fichero para la clave privada, en mi caso pondré la misma dirección del fichero que queremos encriptar.
![](https://github.com/rafael2347/CifradosJava/blob/main/Captura%20de%20pantalla%202024-03-08%20a%20las%2010.17.58.png)<br>
Nos pedirá una una contraseña segura para que el archivo solo se pueda desencriptar con esa contraseña.
![](https://github.com/rafael2347/CifradosJava/blob/main/Captura%20de%20pantalla%202024-03-08%20a%20las%2010.18.12.png)<br>
Listo, el archivo se abrá cifrado correctamente.
![](https://github.com/rafael2347/CifradosJava/blob/main/Captura%20de%20pantalla%202024-03-08%20a%20las%2010.18.28.png)<br>


### Pre-requisitos 📋

_Requisitos:
Tener java instalado, JDK22 y tener Intellij o NetBeans instalado para poder lanzar el programa _

## Libro: Seguridad, criptografía y comercio electrónico con Java 📚

_Este código está cogido de la página 139 y 140 del libro Seguridad, criptografía y comercio electrónico con Java_

* **Fernando López Hernández** - *Creador del libro*
* **Rafa González** - *Documentación y prueba de código* - ([https://github.com/rafael2347](https://github.com/rafael2347))

También puedes mirar la lista de todos los [contribuyentes](https://github.com/your/project/contributors) quíenes han participado en este proyecto. 

## Licencia 📄

Este proyecto está bajo licencia (BSD 3-Clause "New" or "Revised" License)

---
