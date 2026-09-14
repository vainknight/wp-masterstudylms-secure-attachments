<?php
/**
 * Plugin Name: MasterStudy Secure Attachments
 * Description: Bloquea el acceso directo a archivos de materiales de curso (PDF, Word, Excel, ZIP, TXT) en MasterStudy LMS Pro. Solo permite descarga a usuarios logueados con el curso comprado (WooCommerce) o con membresía activa (Paid Memberships Pro). No mueve ni migra archivos existentes.
 * Version: 2.1.0
 * Author: Fran Velazco
 * Author URI: https://www.linkedin.com/in/fran-velazco
 * Text Domain: ms-secure-attachments
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'MSSA_VERSION', '2.1.0' );
define( 'MSSA_QUERY_VAR', 'mssa_file' );

// Extensiones que se bloquean de acceso directo. Cambia esta lista si subes otros tipos.
define( 'MSSA_PROTECTED_EXTENSIONS', array( 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'zip', 'txt' ) );

/**
 * =========================================================================
 * 1. ACTIVACIÓN: añade el bloqueo por extensión al .htaccess de uploads,
 *    SIN mover ningún archivo ni tocar la base de datos.
 * =========================================================================
 */
register_activation_hook( __FILE__, 'mssa_on_activate' );
function mssa_on_activate() {
	mssa_write_htaccess_rules();

	// Necesario para que WordPress reconozca nuestro query var 'mssa_file'
	// en la URL. Sin esto, ?mssa_file=ID no dispara template_redirect con
	// el valor correcto y WordPress sirve la página normal (404 u home).
	add_filter( 'query_vars', function( $vars ) {
		$vars[] = MSSA_QUERY_VAR;
		return $vars;
	});
	flush_rewrite_rules();
}

register_deactivation_hook( __FILE__, 'mssa_on_deactivate' );
function mssa_on_deactivate() {
	mssa_remove_htaccess_rules();
	flush_rewrite_rules();
}

/**
 * Inserta (o actualiza) un bloque de reglas identificado por marcadores,
 * dentro del .htaccess que YA EXISTE (o se crea) en wp-content/uploads/.
 * No se toca ni se sobrescribe ninguna otra regla que ya esté ahí.
 */
function mssa_write_htaccess_rules() {
	$upload_dir  = wp_upload_dir();
	$htaccess    = trailingslashit( $upload_dir['basedir'] ) . '.htaccess';
	$ext_pattern = implode( '|', array_map( 'preg_quote', MSSA_PROTECTED_EXTENSIONS ) );

	$marker_start = '# BEGIN MSSA Secure Attachments';
	$marker_end   = '# END MSSA Secure Attachments';

	$rules  = $marker_start . "\n";
	$rules .= "<FilesMatch \"\\.({$ext_pattern})$\">\n";
	$rules .= "    Order Deny,Allow\n";
	$rules .= "    Deny from all\n";
	$rules .= "    <IfModule mod_authz_core.c>\n";
	$rules .= "        Require all denied\n";
	$rules .= "    </IfModule>\n";
	$rules .= "</FilesMatch>\n";
	$rules .= $marker_end . "\n";

	$existing = file_exists( $htaccess ) ? file_get_contents( $htaccess ) : '';

	// Si ya hay un bloque nuestro de una activación previa, lo removemos primero
	// para no duplicarlo (por ejemplo si cambias la lista de extensiones y reactivas).
	$existing = preg_replace(
		'/' . preg_quote( $marker_start, '/' ) . '.*?' . preg_quote( $marker_end, '/' ) . '\s*/s',
		'',
		$existing
	);

	// Añadimos nuestro bloque AL FINAL, dejando intacto cualquier otro contenido
	// que ya existiera en ese .htaccess (por ejemplo reglas de otro plugin).
	$new_content = rtrim( $existing ) . "\n\n" . $rules;

	file_put_contents( $htaccess, ltrim( $new_content ) );
}

/**
 * Al desactivar el plugin, solo removemos NUESTRO bloque de reglas —
 * cualquier otro contenido del .htaccess queda intacto.
 */
function mssa_remove_htaccess_rules() {
	$upload_dir = wp_upload_dir();
	$htaccess   = trailingslashit( $upload_dir['basedir'] ) . '.htaccess';

	if ( ! file_exists( $htaccess ) ) {
		return;
	}

	$marker_start = '# BEGIN MSSA Secure Attachments';
	$marker_end   = '# END MSSA Secure Attachments';

	$existing = file_get_contents( $htaccess );
	$cleaned  = preg_replace(
		'/' . preg_quote( $marker_start, '/' ) . '.*?' . preg_quote( $marker_end, '/' ) . '\s*/s',
		'',
		$existing
	);

	file_put_contents( $htaccess, $cleaned );
}

/**
 * =========================================================================
 * 2. RUTA DE DESCARGA SEGURA: midominio.com/?mssa_file=ID_DEL_ARCHIVO
 * Lee el archivo desde SU UBICACIÓN ORIGINAL — no se movió nada.
 * =========================================================================
 */
add_filter( 'query_vars', function( $vars ) {
	$vars[] = MSSA_QUERY_VAR;
	return $vars;
});

add_action( 'template_redirect', 'mssa_handle_secure_download', 1 );
function mssa_handle_secure_download() {
	// Leemos también directo de $_GET como red de seguridad: si por
	// cualquier motivo (caché, timing del rewrite) get_query_var() no
	// captura el valor, esto evita que la petición caiga a una página
	// normal de WordPress en vez de a nuestro controlador.
	$attachment_id = get_query_var( MSSA_QUERY_VAR );

	if ( empty( $attachment_id ) && isset( $_GET[ MSSA_QUERY_VAR ] ) ) {
		$attachment_id = sanitize_text_field( wp_unslash( $_GET[ MSSA_QUERY_VAR ] ) );
	}

	if ( empty( $attachment_id ) ) {
		return;
	}

	$attachment_id = absint( $attachment_id );

	nocache_headers();
	header( 'X-Robots-Tag: noindex, nofollow', true );

	if ( ! is_user_logged_in() ) {
		mssa_deny( 403, 'Debes iniciar sesión para acceder a este archivo.' );
	}

	$user_id = get_current_user_id();

	$course_id = mssa_get_course_id_from_attachment( $attachment_id );

	if ( ! $course_id ) {
		mssa_deny( 404, 'Archivo no encontrado o no pertenece a ningún curso.' );
	}

	$has_access = current_user_can( 'manage_options' );

	if ( ! $has_access && mssa_user_purchased_course( $user_id, $course_id ) ) {
		$has_access = true;
	}

	if ( ! $has_access && mssa_user_has_pmpro_access( $user_id, $course_id ) ) {
		$has_access = true;
	}

	if ( ! $has_access ) {
		mssa_deny( 403, 'No tienes acceso a este curso. Debes comprarlo o tener una membresía activa.' );
	}

	mssa_stream_file( $attachment_id );
}

function mssa_deny( $code, $message ) {
	status_header( $code );
	wp_die( esc_html( $message ), esc_html__( 'Acceso restringido', 'ms-secure-attachments' ), array( 'response' => $code ) );
}

/**
 * =========================================================================
 * 3. LÓGICA DE NEGOCIO: MasterStudy / WooCommerce / Paid Memberships Pro
 * Estructura confirmada vía Query Monitor en esta instalación.
 * =========================================================================
 */

/**
 * Dado el attachment_id de un archivo (ej. 8958), encuentra el course_id
 * al que pertenece, siguiendo la cadena real confirmada por SQL directo:
 *
 * 1. El attachment_id vive dentro del meta 'lesson_files' de la LECCIÓN
 *    (post_type 'stm-lessons'), como array serializado, ej: [8958]
 * 2. Esa lección (su post_id) aparece como 'post_id' en
 *    wp_stm_lms_curriculum_materials, que tiene el section_id.
 * 3. wp_stm_lms_curriculum_sections.id = ese section_id -> tiene course_id.
 */
function mssa_get_course_id_from_attachment( $attachment_id ) {
	global $wpdb;

	// Paso 1: buscar la lección cuyo meta 'lesson_files' contiene este attachment_id.
	// Buscamos por coincidencia del número exacto dentro del array serializado,
	// con separadores para no confundir 8958 con 89581, por ejemplo.
	$lesson_id = $wpdb->get_var( $wpdb->prepare(
		"SELECT post_id FROM {$wpdb->postmeta}
		 WHERE meta_key = 'lesson_files'
		 AND ( meta_value LIKE %s OR meta_value LIKE %s OR meta_value LIKE %s OR meta_value = %s )
		 LIMIT 1",
		'%:' . $attachment_id . ';%',      // ej. i:0;i:8958;
		'[' . $attachment_id . ']',         // ej. [8958] (formato JSON-like visto en phpMyAdmin)
		'%,' . $attachment_id . ',%',       // en medio de una lista con comas
		(string) $attachment_id
	) );

	if ( ! $lesson_id ) {
		// Fallback más laxo: LIKE simple con el número en cualquier parte.
		$lesson_id = $wpdb->get_var( $wpdb->prepare(
			"SELECT post_id FROM {$wpdb->postmeta}
			 WHERE meta_key = 'lesson_files'
			 AND meta_value LIKE %s
			 LIMIT 1",
			'%' . $wpdb->esc_like( $attachment_id ) . '%'
		) );
	}

	if ( ! $lesson_id ) {
		return 0;
	}

	// Paso 2: la lección -> section_id, vía wp_stm_lms_curriculum_materials.
	$section_id = $wpdb->get_var( $wpdb->prepare(
		"SELECT section_id FROM {$wpdb->prefix}stm_lms_curriculum_materials
		 WHERE post_id = %d
		 LIMIT 1",
		$lesson_id
	) );

	if ( ! $section_id ) {
		return 0;
	}

	// Paso 3: section_id -> course_id.
	$course_id = $wpdb->get_var( $wpdb->prepare(
		"SELECT course_id FROM {$wpdb->prefix}stm_lms_curriculum_sections
		 WHERE id = %d
		 LIMIT 1",
		$section_id
	) );

	return $course_id ? absint( $course_id ) : 0;
}

/**
 * Verifica compra del curso vía la función nativa de MasterStudy.
 */
function mssa_user_purchased_course( $user_id, $course_id ) {
	if ( function_exists( 'stm_lms_get_user_course' ) ) {
		$user_course = stm_lms_get_user_course( $user_id, $course_id );
		return ! empty( $user_course );
	}

	global $wpdb;
	$exists = $wpdb->get_var( $wpdb->prepare(
		"SELECT COUNT(*) FROM {$wpdb->prefix}stm_lms_user_courses WHERE user_id = %d AND course_id = %d",
		$user_id,
		$course_id
	) );

	return $exists > 0;
}

/**
 * Verifica membresía PMPro. PMPro registra su restricción sobre el
 * page_id de la LECCIÓN individual, así que revisamos el curso y,
 * si no hay restricción ahí, cada lección del curso.
 */
function mssa_user_has_pmpro_access( $user_id, $course_id ) {
	if ( ! function_exists( 'pmpro_has_membership_access' ) ) {
		return false;
	}

	if ( mssa_check_pmpro_page_access( $course_id, $user_id ) ) {
		return true;
	}

	global $wpdb;
	$lesson_ids = $wpdb->get_col( $wpdb->prepare(
		"SELECT m.post_id
		 FROM {$wpdb->prefix}stm_lms_curriculum_materials m
		 INNER JOIN {$wpdb->prefix}stm_lms_curriculum_sections s ON m.section_id = s.id
		 WHERE s.course_id = %d",
		$course_id
	) );

	foreach ( $lesson_ids as $lesson_id ) {
		if ( mssa_check_pmpro_page_access( $lesson_id, $user_id ) ) {
			return true;
		}
	}

	return false;
}

function mssa_check_pmpro_page_access( $page_id, $user_id ) {
	$has_access = pmpro_has_membership_access( $page_id, $user_id );

	if ( is_array( $has_access ) ) {
		return (bool) $has_access[0];
	}

	return (bool) $has_access;
}

/**
 * =========================================================================
 * 4. ENTREGA DEL ARCHIVO — desde su ruta original, sin haber sido movido.
 * =========================================================================
 */
function mssa_stream_file( $attachment_id ) {
	$file_path = mssa_resolve_attachment_path( $attachment_id );

	if ( ! $file_path || ! file_exists( $file_path ) ) {
		mssa_deny( 404, 'El archivo ya no existe en el servidor.' );
	}

	$mime_type = get_post_mime_type( $attachment_id );
	if ( ! $mime_type ) {
		$mime_type = 'application/octet-stream';
	}

	$filename = basename( $file_path );

	while ( ob_get_level() ) {
		ob_end_clean();
	}

	header( 'Content-Type: ' . $mime_type );
	header( 'Content-Disposition: inline; filename="' . $filename . '"' );
	header( 'Content-Length: ' . filesize( $file_path ) );
	header( 'X-Content-Type-Options: nosniff' );

	readfile( $file_path );
	exit;
}

/**
 * Resuelve la ruta física real de un adjunto, corrigiendo el caso (visto
 * en esta instalación) donde '_wp_attached_file' trae un slash inicial
 * de más (ej. '/Archivo.pdf' en vez de '2026/09/Archivo.pdf'), lo que
 * hace que get_attached_file() arme una ruta con doble slash y falle
 * la comprobación file_exists().
 */
function mssa_resolve_attachment_path( $attachment_id ) {
	// Primero, el intento normal de WordPress.
	$file_path = get_attached_file( $attachment_id );

	if ( $file_path && file_exists( $file_path ) ) {
		return $file_path;
	}

	// Si falló, reconstruimos manualmente a partir del meta crudo,
	// quitando cualquier slash inicial que cause el doble slash.
	$relative_path = get_post_meta( $attachment_id, '_wp_attached_file', true );

	if ( ! $relative_path ) {
		return false;
	}

	$relative_path = ltrim( $relative_path, '/' );

	$upload_dir = wp_upload_dir();
	$candidate  = trailingslashit( $upload_dir['basedir'] ) . $relative_path;

	if ( file_exists( $candidate ) ) {
		return $candidate;
	}

	return false;
}

/**
 * =========================================================================
 * 5. HELPER: genera la URL segura para un attachment_id.
 * =========================================================================
 */
function mssa_get_secure_url( $attachment_id ) {
	return add_query_arg( MSSA_QUERY_VAR, absint( $attachment_id ), home_url( '/' ) );
}

/**
 * =========================================================================
 * 6. REESCRITURA AUTOMÁTICA DE ENLACES: convierte cualquier URL directa de
 * uploads (para las extensiones protegidas) que MasterStudy imprima en el
 * HTML de la lección, en la URL segura — sin tocar la base de datos.
 * Esto es lo que hace que el botón de descarga existente siga funcionando.
 * =========================================================================
 */
add_filter( 'the_content', 'mssa_rewrite_protected_urls_in_content', 20 );
function mssa_rewrite_protected_urls_in_content( $content ) {
	if ( ! is_singular() || empty( $content ) ) {
		return $content;
	}
	return mssa_rewrite_urls_helper( $content );
}

/**
 * MasterStudy renderiza los materiales de lección vía su propio shortcode/
 * template, no siempre a través de "the_content". Este filtro adicional
 * intercepta la salida completa del buffer de la página del curso/lección
 * como red de seguridad, para capturar el HTML sin importar de dónde salga.
 * Solo actúa en páginas de curso/lección (no en todo el sitio) para no
 * afectar rendimiento en el resto.
 */
add_action( 'template_redirect', 'mssa_maybe_buffer_output', 1 );
function mssa_maybe_buffer_output() {
	if ( is_admin() ) {
		return;
	}

	// Solo si la URL sugiere que estamos en una vista de curso/lección de MasterStudy.
	// Ajusta este patrón si tu estructura de URLs de curso difiere.
	$uri = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '';
	if ( strpos( $uri, 'course' ) === false && strpos( $uri, 'curso' ) === false && strpos( $uri, 'mi-cuenta' ) === false ) {
		return;
	}

	ob_start( 'mssa_rewrite_urls_helper' );
}

function mssa_rewrite_urls_helper( $html ) {
	$upload_dir  = wp_upload_dir();
	$upload_base = $upload_dir['baseurl'];
	$ext_pattern = implode( '|', array_map( 'preg_quote', MSSA_PROTECTED_EXTENSIONS ) );

	// Busca URLs de uploads con esas extensiones y las reemplaza por la URL segura.
	return preg_replace_callback(
		'#' . preg_quote( $upload_base, '#' ) . '/[^\s"\'<>]+\.(?:' . $ext_pattern . ')#i',
		function( $matches ) {
			$url           = $matches[0];
			$attachment_id = attachment_url_to_postid( $url );

			if ( ! $attachment_id ) {
				return $url; // no se pudo resolver, deja la URL original tal cual
			}

			return mssa_get_secure_url( $attachment_id );
		},
		$html
	);
}
