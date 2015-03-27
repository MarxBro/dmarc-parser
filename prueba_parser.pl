#!/usr/bin/perl
######################################################################
# DMARC Reporte
######################################################################

use strict;
use warnings;
use feature "say";
use Getopt::Std;
use Pod::Usage;
use Term::ANSIColor;
use Data::Dumper;

=pod

=encoding utf8

=head1 SYNOPSIS

Este programa sirve para procesar la informacion recibida en algun reporte DMARC,
acerca del envio de correos y la relacion entre estos y los registro spf y dkim.

=cut

my %opts = ();
getopts('hdtai:',\%opts);

# Ayuda y final feliz.
ayudas() if $opts{h};
exit if $opts{h};

$opts{i} or die "Error: Especifique un archivo en la entrada con la opcion -i Archivo.xml.
    FINAL NO FELIZ.";


=pod

=head1 Argumentos

Este programa es muy simple y toma unos pocos parametros.

=over

=item * B<-i>       Archivo input (El xml del reporte). [EXCLUYENTE]

=item * B<-h>       (Esta) Ayuda.

=item * B<-d>       Debug flag.

=item * B<-t>       Imprime TODO como hashref, solamente.

=item * B<-a>       Imprime solamente los totales.

=back

El programa B<necesita> excluyentemete de un archivo en la entrada, bajo el parametro B<i>. Si esta ausente, falla.

Sin argumentos adicionales, imprime todo con colorines porque todos aman los colores. :P

=cut


# El archivo del modulo tiene que estar en la misma carpeta.
use Parser_XML_DMARC;

=pod

=head1 Importante

Este programita se vale del modulo que lo acompaña y es poco mas que un ejemplo practico.

Ambos archivos debiesen estar en la misma carpeta.

Ver el codigo de este archivo es la mejor documentacion posible sobre los metodos que el modulo implemnta y su utilizacion.

=cut

my $debug = $opts{d};

my $dmarc_reporte = Parser_XML_DMARC->new( { 
    archivo_input => "$opts{i}"
    });


# Utilizar todos los metodod del objeto, solo por fines ilustrativos.

my $hashref_todo_el_reporte = $dmarc_reporte->archivo;

my ($fecha_inicio_reporte,$fecha_final_reporte) = $dmarc_reporte->fecha_reporte;

my $entidad_emisora_del_reporte = $dmarc_reporte->emisor;

my $entidad_emisora_del_reportei_email = $dmarc_reporte->emisor_mail;

my $mi_dominio_url = $dmarc_reporte->mi_dominio;

# Politicas !
my @politicas_posibles = $dmarc_reporte->politicas_pub_nombres;
my $p_string = join(',',@politicas_posibles);

my %politicas_publicadas_por_mi_dominio = $dmarc_reporte->politicas_pub(split(/,/,$p_string));
#my %politicas_publicadas_por_mi_dominio = $dmarc_reporte->politicas_pub($consulta_politicas_de_mi_dominio);

my @reporte_dkim = $dmarc_reporte->reporte_mails_dkim;
my @reporte_spf = $dmarc_reporte->reporte_mails_spf;

my %dmarc_reporte_totales = $dmarc_reporte->totales_envios;


######################################################################
# Pretty Print Area.
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
say colored($mi_dominio_url,$c);
say $separador_main;
say $indentin, $bullet, "DESDE= ",colored($fecha_inicio_reporte,$c);
say $indentin, $bullet, "HASTA= ",colored($fecha_final_reporte,$c);
say " ";

    ## Politicas Publicadas
say $separador;
say colored("Politicas Publicadas",$c);
say $separador;
foreach my $k (keys (%politicas_publicadas_por_mi_dominio)){
    say $indentin, colored($k,$c),$indentin, $politicas_publicadas_por_mi_dominio{$k};
}
say " ";

    ## Reporteada de envios.
say $separador;
say colored("Envios",$c);
say $separador;
my ($dkim_fails,$dkim_total,$dkimpercent) = split(/ /,$dmarc_reporte_totales{'DKIM'});
my ($spf_fails,$spf_total,$spfpercent) =  split(/ /,$dmarc_reporte_totales{'SPF'});

say "Envios Totales = ", $indentin,colored ("$dkim_total - $spf_total",$c);
say " ";


say $bullet,$indentin,colored("DKIM FAILS = ",$c),$indentin, colored("$dkim_fails",$c),$indentin, colored($dkimpercent,$c2);

foreach my $ln (@reporte_dkim){
    unless ($ln =~ m/pass$/){
        my @a = split(/ /,$ln);
        say $indentin, $bullet, $indentin, "IP: $a[2] ","CAUSA:: ", colored($a[4],$c2)," --  Dominio Emisor::  $a[0]";
    }
}
say " ";


say $bullet,$indentin,colored("SPF FAILS = ",$c),$indentin, colored("$spf_fails",$c),$indentin, colored($spfpercent,$c2);

foreach my $ln (@reporte_spf){
    unless ($ln =~ m/pass$/){
        my @a = split(/ /,$ln);
        say $indentin, $bullet, $indentin, "IP: $a[2] ","CAUSA:: ", colored($a[4],$c2)," -- Dominio Emisor::  $a[0]";
    }
}
say " ";

######################################################################
# Subs
######################################################################
sub ayudas {
    pod2usage(-verbose=>3);
}

=pod

=head1 Autor y Licencia.

Programado por B<Marxbro> aka B<Gstv>, ditribuir solo bajo la licencia
WTFPL: I<Do What the Fuck You Want To Public License>.

Zaijian.

=cut

