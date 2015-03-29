#!/usr/bin/perl
######################################################################
# Modulo que parsea un archivo DMARC y devuelve un hashref con la
# informacion que incluye.
######################################################################

package Parser_XML_DMARC;

use strict;

use Class::Tiny qw( archivo_input archivo fecha_reporte emisor 
                    politicas_pub politicas_pub_nombres emisor_mail 
                    totales_envios reporte_mails_dkim 
                    reporte_mails_spf mi_dominio);
use XML::Simple;
use POSIX q/strftime/;
use Carp;
use Data::Dumper;

######################################################################
# DOCS
######################################################################
=pod

=encoding utf8

=head1 Parser de reportes DMARC

Este modulo tiene como proposito facilitar ciertas tareas relacionadas
con los datos que llegan como reporte de las politicas de los
dominios emisores de mail.

La idea es simple: un modulo para obtener informacion de esos archivos
que se envian al administrador del dominio.

=head1 SYNOPSIS

Este modulo sirve para parsear un reporte DMARC.

Es un objeto e importa metodos que realizan tareas, procesando la
informacion presente en el reporte.

=head2 Forma de uso:

Inicializar pasando como valor al parametro B<archivo> el nombre
del archivo a parsear.

I<Este tiene que ser un XML!>

=head1 Acerca del protocolo DMARC

El protocolo DMARC es bastante moderno y complemento intentos anteriores de
prevenir y documentar el abuso -spam, phising...- a las políticas de mailiing por parte de los
dueños de los dominios que ejecutan la infraestructura (como Google,
Facebook, PayPal, etc.)

DMARC complementa a SPF y DKIM. En si mismo, un reporte DMARC informa al
administrador todos los mails que salieron desde su servidor hacia el servidor
que informa (y envia el reporte), detallando desde que IP salió y el resultado
de la implementación de la política DMAR implementada.

Ver L<http://www.ietf.org/id/draft-kucherawy-dmarc-base-04.txt> para obtener
información calificada acerca del protocolo DMARC, su implementación y utilización.

=cut

######################################################################
# VARIABLES COMUNES
######################################################################
my (
    $todo_el_archivo,                @politicas_publicadas_validas,
    $cuenta_totales_envio_spf,       $cuenta_totales_envio_dkim,
    $cuenta_totales_envio_FAILS_spf, $cuenta_totales_envio_FAILS_dkim
);

my $debug = 0; # Debug flag.

# Constructor !
sub BUILD {
    my ( $self, $args ) = @_;
    for my $req (qw/archivo_input/) {
        croak "ERROR: El atributo $req es necesario!" unless defined $self->$req;
    }
    my $xml = new XML::Simple;
    $todo_el_archivo = $xml->XMLin( $self->archivo_input );
    print Dumper($todo_el_archivo) if $debug;
    @politicas_publicadas_validas = (qw(p aspf sp pct adkim domain));
}

###########
# METODOS #
###########

######################################################################
=pod

=head1 METODOS

Los siguientes metodos estan disponibles:

=over

=item * B<archivo_input>

=item * B<archivo>

=item * B<fecha_reporte>

=item * B<emisor>

=item * B<politicas_pub>

=item * B<politicas_pub_nombres>

=item * B<emisor_mail>

=item * B<totales_envios>

=item * B<reporte_mails_dkim>

=item * B<reporte_mails_spf>

=back

=cut

######################################################################
=pod

=head2 archivo

Este metodo devuelve todo el reporte en formato hashref.

=cut

sub archivo {
    my $self = shift;
    return $todo_el_archivo;
}

######################################################################
=pod

=head2 fecha_reporte

Este metodo devuelve la fecha de inicio del reporte, seguida por la fecha final del periodo.

Las dos son variables; utilizar variables simples para obtener los valores.

=cut
sub fecha_reporte {
    my $self = shift;
    my $fecha_inicio = scalar localtime( $todo_el_archivo->{'report_metadata'}{'date_range'}{'begin'} );
    my $fecha_final = scalar localtime( $todo_el_archivo->{'report_metadata'}{'date_range'}{'end'} );
    # Devuelve una lista cuyo primer argumento es la fecha de inicio, 
    # seguida de la fecha final.
    return ( $fecha_inicio, $fecha_final );
}

######################################################################
=pod

=head2 emisor

Este metodo devuelve la organizacion emisora del repote.

=cut
sub emisor {
    my $self           = shift;
    my $emisor_reporte = $todo_el_archivo->{"report_metadata"}{"org_name"};
    return $emisor_reporte;
}

######################################################################
=pod

=head2 mi_dominio

Este metodo devuelve el nombre de mi dominio, tal como aparece en 
el header de los mails enviados.

=cut
sub mi_dominio {
    my $self = shift;
    my $mi_dominio_nombre = $todo_el_archivo->{"policy_published"}{"domain"};
    return $mi_dominio_nombre;
}

######################################################################
=pod

=head2 emisor_mail

Este metodo devuelve unicamente el mail de la organizacion emisora.

=cut
sub emisor_mail {
    my $self           = shift;
    my $emisor_mail = $todo_el_archivo->{"report_metadata"}{"email"};
    return $emisor_mail;
}

######################################################################
=pod

=head2 politicas_pub

Metodo para devolver las politicas publicadas por el dueño del dominio.

I<Retorna un hash>, cuyos keys corresponden con las politicas consultadas.

I<Toma como argumentos las politicas a consultar>, que pueden ser cualquiera 
de las siguientes -generalmente, para un dominio con spf, dkim y dmarc-:

=over

=item * B<p>

=item * B<aspf>

=item * B<sp>

=item * B<pct>

=item * B<adkim>

=item * B<domain>

=back

=cut
sub politicas_pub {
    my ( $self, @args ) = @_;
    my %return_stuff = ();
    my $rgx_pp = join('|',@politicas_publicadas_validas);
    foreach my $consulta (@args){
        unless ($consulta =~ m/$rgx_pp/gi) {
            carp "La politica --> $consulta <-- no es valida. Pasando de largo...";
            next;
        }
        $return_stuff{$consulta} = $todo_el_archivo->{"policy_published"}{"$consulta"};
    }
    return %return_stuff;
}

######################################################################
=pod

=head2 politicas_pub_nombres

Metodo para devolver una lista de las politicas posibles.

Es solo un complemento del metodo anterior, I<y devuelve los elementos presentes 
de la lista de arriba>, como array.

=cut
sub politicas_pub_nombres {
    my $self = shift;
    my @p_p_existentes = ();
    foreach my $p_p (@politicas_publicadas_validas){
        if (exists $todo_el_archivo->{"policy_published"}{"$p_p"}){
            push(@p_p_existentes,$p_p);
        }
    }
    return @p_p_existentes;
}

######################################################################
=pod

=head2 reporte_mails_dkim

Este metodo parsea el reporte en busqueda de la cantidad de mails que se  enviaron 
y su resultado de autentificacion DKIM.

I<Devuelve un string>.

=head3 FORMATO DEL STRING.

B<dominio emisor - cantidad - ip emisora - Dominio dkim - resultado dkim>

=cut
sub reporte_mails_dkim {
    my $self = shift;
    my @array_retornable = ();
    my $ha = 0;

    if (ref($todo_el_archivo->{"record"}) eq 'ARRAY'){
        foreach (0 .. $#{ $todo_el_archivo->{"record"} }) {
            my $cantidad_dkim           = $todo_el_archivo->{"record"}[$ha]{'row'}{'count'};
            my $ip_emisora              = $todo_el_archivo->{"record"}[$ha]{'row'}{'source_ip'};
            my $resultado_dkim          = $todo_el_archivo->{"record"}[$ha]{'auth_results'}{'dkim'}{'result'}; 
            my $dominio_records_dkim    = $todo_el_archivo->{"record"}[$ha]{'auth_results'}{'dkim'}{'domain'};
            my $dominio_emisor          = $todo_el_archivo->{"record"}[$ha]{'identifiers'}{'header_from'};
            my $lna_pra_push = join(" ",($dominio_emisor,$cantidad_dkim,$ip_emisora,$dominio_records_dkim,$resultado_dkim));
            push(@array_retornable,$lna_pra_push);
            $ha++;
            $cuenta_totales_envio_dkim += $cantidad_dkim;
            unless ($resultado_dkim eq 'pass'){
                $cuenta_totales_envio_FAILS_dkim += $cantidad_dkim;
            }
        }
    } else{
        my $cantidad_dkim           = $todo_el_archivo->{"record"}{'row'}{'count'};
        my $ip_emisora              = $todo_el_archivo->{"record"}{'row'}{'source_ip'};
        my $resultado_dkim          = $todo_el_archivo->{"record"}{'auth_results'}{'dkim'}{'result'}; 
        my $dominio_records_dkim    = $todo_el_archivo->{"record"}{'auth_results'}{'dkim'}{'domain'};
        my $dominio_emisor          = $todo_el_archivo->{"record"}{'identifiers'}{'header_from'};
        my $lna_pra_push = join(" ",($dominio_emisor,$cantidad_dkim,$ip_emisora,$dominio_records_dkim,$resultado_dkim));
        push(@array_retornable,$lna_pra_push);
        $cuenta_totales_envio_dkim += $cantidad_dkim;
        unless ($resultado_dkim eq 'pass'){
            $cuenta_totales_envio_FAILS_dkim += $cantidad_dkim;
        }
    }

    return @array_retornable;
}

######################################################################
=pod

=head2 reporte_mails_spf

Este metodo es un clon del de arriba, pero para spf. Parsea el reporte en busqueda 
de la cantidad de mails que se enviaron y su resultado de autentificacion B<SPF>.

I<Devuelve un string.>

=head3 FORMATO DEL STRING.

B<dominio emisor - cantidad - ip emisora - Dominio spf - resultado spf>

=cut

sub reporte_mails_spf {
    my $self = shift;
    my @array_retornable = ();
    my $ha = 0;

    if (ref($todo_el_archivo->{"record"}) eq 'ARRAY'){
        foreach (0 .. $#{ $todo_el_archivo->{"record"} }) {
            my $cantidad_spf           = $todo_el_archivo->{"record"}[$ha]{'row'}{'count'};
            my $ip_emisora             = $todo_el_archivo->{"record"}[$ha]{'row'}{'source_ip'};
            my $resultado_spf          = $todo_el_archivo->{"record"}[$ha]{'auth_results'}{'spf'}{'result'}; 
            my $dominio_records_spf    = $todo_el_archivo->{"record"}[$ha]{'auth_results'}{'spf'}{'domain'};
            my $dominio_emisor         = $todo_el_archivo->{"record"}[$ha]{'identifiers'}{'header_from'};
            my $lna_pra_push = join(" ",($dominio_emisor,$cantidad_spf,$ip_emisora,$dominio_records_spf,$resultado_spf));
            push(@array_retornable,$lna_pra_push);
            $ha++;
            $cuenta_totales_envio_spf += $cantidad_spf;
            unless ($resultado_spf eq 'pass'){
                $cuenta_totales_envio_FAILS_spf += $cantidad_spf;
            }
        }
    } else{
        my $cantidad_spf           = $todo_el_archivo->{"record"}{'row'}{'count'};
        my $ip_emisora             = $todo_el_archivo->{"record"}{'row'}{'source_ip'};
        my $resultado_spf          = $todo_el_archivo->{"record"}{'auth_results'}{'spf'}{'result'}; 
        my $dominio_records_spf    = $todo_el_archivo->{"record"}{'auth_results'}{'spf'}{'domain'};
        my $dominio_emisor         = $todo_el_archivo->{"record"}{'identifiers'}{'header_from'};
        my $lna_pra_push = join(" ",($dominio_emisor,$cantidad_spf,$ip_emisora,$dominio_records_spf,$resultado_spf));
        push(@array_retornable,$lna_pra_push);
        $cuenta_totales_envio_spf += $cantidad_spf;
        unless ($resultado_spf eq 'pass'){
            $cuenta_totales_envio_FAILS_spf += $cantidad_spf;
        }
    }

    return @array_retornable;
}

######################################################################
=pod

=head2 totales_envios 

Este metodo devuelve el total de mails que fallaron, el total de mails enviados y 
el porcentaje de errores (entre ambos).

Devuelve un hash con dos keys B<SPF> y B<DKIM>, cuyo valor es un string con el 
total de mails fallidos, el total de envios y el porcentaje, como se dijo anteriormente.

Retorna separado por espacios, como todos los metodos superiores.

=cut

sub totales_envios {
    my $self = shift;
    my ($percent_spf,$percent_dkim);
    if ($cuenta_totales_envio_spf == 0){
        $percent_spf = 0;
    } else {
        $percent_spf = $cuenta_totales_envio_FAILS_spf / $cuenta_totales_envio_spf * 100;
    }
    if ($cuenta_totales_envio_dkim == 0){
        $percent_dkim = 0;
    } else {
        $percent_dkim = $cuenta_totales_envio_FAILS_dkim / $cuenta_totales_envio_dkim * 100;
    }
    my %linea_fin = ();
    $linea_fin{'DKIM'} = "$cuenta_totales_envio_FAILS_dkim $cuenta_totales_envio_dkim $percent_dkim";
    $linea_fin{'SPF'} = "$cuenta_totales_envio_FAILS_spf $cuenta_totales_envio_spf $percent_spf";
    return %linea_fin;
}


######################################################################
=pod

=head1 Como mierrrrrrrrrd... funciona el DMARC?

En unos minutos, así funciona la evaluación que se reporta por XML.

La organización emisora del reporte colecciona información sobre los mails que recibe, provenientes
de nuetro dominio.

Acorde a esta política, busca como los **records** dkim y spf se I<alinean>. Esta es la última acción
a tomar por su parte respecto a aceptar o no nuestros mails como B<legítimos>.

Llegado este punto, es todo mas claro: la dirección IP de los emisarios de esos correos que "dicen" ser
enviados por nuestro dominio son evaluadas en busqueda de políticas spf y dkim (reverse DNS query).

Si las politicas asociadas a nuestro dominio incluyen esa IP como emisor permitido y viceversa, todos
los campos están alineados y la política que utilizamos será respetada: B<esos mails fueron legítimamente enviados>.

SI, por lo contrario, la/s IPs asociadas no pertenecieran a nuestro dominio o dominios declarados como
posibles emisarios (bajo nuestra bendición), el resultado de la autentificación será negativo y claramente
B<esos mensajes fueron enviados ilegítimamente en nuestro nombre>.

B<Y si mis mensajes legitimos son interpretados equivocadamente como ilegimos?>

Existe una posibilidad de que mensajes ilegitmos sean interpretados como legítimos si la política
expresada en nuestro DNS (spf y DMARC) es -muy- permisiva.

Por ultimo, existe una posibilidad de que mensajes legítimos sean interpretados como SPAM o Phising si
las políticas elegidas y declaradas son incoherentes.

(( La gente que sabe, recomienda utiliar politicas flexibles, I<soft-fail> en lugar de I<reject>.))

=head1 Ah... Entonces porque este modulo?

Porque se me canto el forro de las pelot... Mentira, porque necesitaba algo que haga esto y me 
puse a programar un poquito.

"Oia, por que no hacer un modulo?" Me dije. Esa es tooda la historia.

Nunca nadie va a leer esto, en la misma forma en que nunca nadie va a leer lo que dicen 
esos reportes; tener un programa que lo haga es una buena idea.

=head1 Autor y Licencia.

Programado por B<Marxbro> aka B<Gstv>, en los calurosos dias del comienzo de Marzo del 2015.

Distribuir solo bajo la licencia
WTFPL: I<Do What the Fuck You Want To Public License>.

Zaijian.

=cut

1;
