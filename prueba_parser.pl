#!/usr/bin/perl
######################################################################
# DMARC Parser y Reporte
######################################################################

use strict;
#use warnings;
use feature "say";
use Getopt::Std;
use Pod::Usage;
use Term::ANSIColor;
use Data::Dumper;

=pod

=encoding utf8

=head1 SYNOPSIS

Este programa sirve para procesar la informacion recibida en algun reporte DMARC,
acerca del envio de correos y la relacion entre estos y los registros spf y dkim.

=cut

my %opts = ();
getopts('hdtai:',\%opts);

# Ayuda y final feliz.
pod2usage( -verbose => 3, exitval => 0 ) if $opts{h};
exit if $opts{h};

# Chequear si la salida esta redireccionada a una pipa.
my $ss = 0;
if (-t STDOUT){
    $ss++;
}


$opts{i} or die "Error: Especifique un archivo en la entrada con la opcion -i Archivo.xml.
    FINAL NO FELIZ.";


=pod

=head1 Argumentos

Este programa es muy simple y toma unos pocos parametros.

=over

=item * B<-i>       Archivo input (El xml del reporte). [OBLIGATORIO]

=item * B<-h>       (Esta) Ayuda.

=item * B<-d>       Debug flag.

=item * B<-t>       Imprime TODO como hashref, solamente.

=item * B<-a>       Imprime solamente los totales.

=back

El programa B<necesita> de un archivo en la entrada, bajo el parametro B<i>. 

Si esta ausente, falla.

Sin argumentos adicionales imprime un reporte exhaustivo.

Si la salida es la consola imprime con colores (porque todos aman los colores :P).
Si esta redireccionada a una pipa, suprime todos los colores.

=cut


# El archivo del modulo tiene que estar en la misma carpeta.
use Parser_XML_DMARC;

=pod

=head1 Importante

Este programita se vale del modulo que lo acompaña y es 
poco mas que un ejemplo practico.

Ambos archivos debiesen estar en la misma carpeta.

Ver el codigo de este archivo es la mejor documentacion posible sobre 
los metodos que el modulo implemnta y su utilizacion.

=cut

my $debug = $opts{d};

my $dmarc_reporte = Parser_XML_DMARC->new( { 
    archivo_input => "$opts{i}"
    });


# Todos los metodos del objeto.

my $hashref_todo_el_reporte = $dmarc_reporte->archivo;

my ($fecha_inicio_reporte,$fecha_final_reporte) = $dmarc_reporte->fecha_reporte;

my $entidad_emisora_del_reporte = $dmarc_reporte->emisor;

my $entidad_emisora_del_reportei_email = $dmarc_reporte->emisor_mail;

my $mi_dominio_url = $dmarc_reporte->mi_dominio;

# Politicas !
my @politicas_posibles = $dmarc_reporte->politicas_pub_nombres;
my $p_string = join(',',@politicas_posibles);

my %politicas_publicadas_por_mi_dominio = $dmarc_reporte->politicas_pub(split(/,/,$p_string));

my @reporte_dkim = $dmarc_reporte->reporte_mails_dkim;
my @reporte_spf = $dmarc_reporte->reporte_mails_spf;

my %dmarc_reporte_totales = $dmarc_reporte->totales_envios;


######################################################################
# Imprimir como un campeon 
######################################################################

my $separador = '-'x80;
my $separador_main = '='x80;
my $bullet = '+* ';
my $indentin = '  ';
my $c = 'bright_yellow on_black';
my $c2 = 'bright_green on_black';

if ($opts{t}){
    print Dumper($hashref_todo_el_reporte);
}

if ($opts{a}){
    say "Record - Fallos - Totales - Porcentaje de Errores";
    say $separador;
    say "DKIM   $dmarc_reporte_totales{'DKIM'}";
    say "SPF    $dmarc_reporte_totales{'SPF'}";
}
exit if ($opts{a} || $opts{t});

# Imprimir tutti el registro.
    ## Datos de la organizacion.
say $separador_main;
say $bullet, g_colored($entidad_emisora_del_reporte,$c), " reporte para el dominio::";
say g_colored($mi_dominio_url,$c);
say $separador_main;
say $indentin, $bullet, "DESDE= ",g_colored($fecha_inicio_reporte,$c);
say $indentin, $bullet, "HASTA= ",g_colored($fecha_final_reporte,$c);
say " ";

    ## Politicas Publicadas
say $separador;
say g_colored("Politicas Publicadas",$c);
say $separador;
foreach my $k (keys (%politicas_publicadas_por_mi_dominio)){
    say $indentin, g_colored($k,$c),$indentin, $politicas_publicadas_por_mi_dominio{$k};
}
say " ";

    ## Reporteada de envios.
say $separador;
say g_colored("Envios",$c);
say $separador;
my ($dkim_fails,$dkim_total,$dkimpercent) = split(/ /,$dmarc_reporte_totales{'DKIM'});
say ($dkim_fails,'-',$dkim_total,'-',$dkimpercent) if $debug;
my ($spf_fails,$spf_total,$spfpercent) =  split(/ /,$dmarc_reporte_totales{'SPF'});
say ($spf_fails,'-',$spf_total,'-',$spfpercent) if $debug;

# Este chequeo solamente seria util en caso de que alguna entidad emsora analice unicamente un tipo de record -Facebook?- o de phishing muuuuy zarpado.
if ($dkim_total != $spf_total){
    say "Envios Totales = ", $indentin,g_colored ("$dkim_total - $spf_total",$c," LA CANTIDAD DE ENVIOSCON RECORD DKIM Y SPF SON DISTINTOS!");
    say " ";
} else {
    if ($dkim_total){
        say "Envios Totales = ", $indentin,g_colored ("$dkim_total",$c), " Correos enviados. ";
        say " ";
    } else {
        say "Envios Totales = ", $indentin,g_colored ("$spf_total",$c), " Correos enviados. ";
        say " ";
    }
}

# DKIM
say $bullet,$indentin,g_colored("DKIM FAILS = ",$c),$indentin, g_colored("$dkim_fails",$c),$indentin, g_colored(sprintf("%2.f",$dkimpercent),$c2), " %";

foreach my $ln (@reporte_dkim){
    unless ($ln =~ m/pass$/){
        my @a = split(/ /,$ln);
        say $indentin, $bullet, $indentin, "IP: $a[2] ","CAUSA:: ", g_colored($a[4],$c2)," --  Dominio Emisor::  $a[0]";
    }
}
say " ";

# Spf
say $bullet,$indentin,g_colored("SPF FAILS = ",$c),$indentin, g_colored("$spf_fails",$c),$indentin, g_colored( (sprintf "%2.f", $spfpercent),$c2), " %";

foreach my $ln (@reporte_spf){
    unless ($ln =~ m/pass$/){
        my @a = split(/ /,$ln);
        say $indentin, $bullet, $indentin, "IP: $a[2] ","CAUSA:: ", g_colored($a[4],$c2)," -- Dominio Emisor::  $a[0]";
    }
}
say " ";

# Esto es solamente para que separe los reportes cuando vayan pipeados a un unico txt. Quedan desprolijos y con muchas lineas,
# asi que le agregue una mas para que empeorando la cosa pueda entender algo! :P.
say " ";
say '@' x 100;
say " ";

######################################################################
# Subs
######################################################################
sub g_colored {
    my $texto = shift;
    my $color_string = shift;
    if ( $ss ){
        return colored($texto, $color_string);
    } else {
        return $texto;
    }

}

=pod

=head1 Entonces... Que hago con esto?

Ja! Esa es la gran pregunta.

Yo, que tengo varios dominios que vigilar del phishing, hago esto en un directorio con todos los reportes nuevos:

C<for i in *.xml; do ./prueba_parser.pl -i $i E<gt>E<gt> Salida.txt; done>

Pero Ud. haga lo que quiera (ver abajo).

=head1 Autor y Licencia.

Programado por B<Marxbro> aka B<Gstv>, en Marzo del 2015. 

Distribuir solo bajo la licencia WTFPL: I<Do What the Fuck You Want To Public License>.

Zaijian.

=cut


