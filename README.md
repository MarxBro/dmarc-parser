# dmarc-parser

Este proyecto no es más que un medio para obtener la información de los reportes DMARC.

Es un scriptcito, simple y simpaticón, que se vale de un módulo aún más simple -pero más amargado- que imprime en la consola información sobre los correos enviados por los dominios que "administro".

Por el momento hace esto:

* Lee un archivo xml y parsea toda la información disponible (opcionalmente, devuelve un hashref con esta data).

* Implementa medios de obtener informaciones puntuales del xml, como por ejemplo la cantidad de correos que fallaron en la alineación spf y/o dkim, la ip del emisor, etc. etc.

* Genera un reporte en la terminal con la información (más o menos) jerarquizada y presentable. No es muy estética la salida, pero mejor que leer puro xml seguro.

Dejo una captura de pantalla por ahi...

# TODO

Estaria bueno que vaya a una DB.

Estaria bueno que tenga interfaz web.

