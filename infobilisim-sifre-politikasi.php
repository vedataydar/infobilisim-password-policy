<?php
/*
Plugin Name: Zorunlu Güçlü Şifre Politikası (MU)
Description: Tüm kullanıcılar için (Kayıt, Güncelleme, Sıfırlama) güçlü şifre kurallarını zorunlu kılar.
Version: 1.3
Author: Vedat Aydar
Author URI: https://buymeacoffee.com/vedataydar

Company: INFO Bilişim Yazılım ve İnternet Hizmetleri
Donate:  https://buymeacoffee.com/vedataydar
*/

// Dosyaya doğrudan erişimi engelle
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Yardımcı Fonksiyon: Şifre Politikası Kontrolü
 * Bu fonksiyon bir şey döndürmez (void), referans alınan $errors nesnesini doğrudan işler.
 */
function enforce_strong_password_policy( $errors, $password, $username = '', $email = '' ) {

    // Şifre boşsa, kontrol etmeyi bırak ve fonksiyondan çık.
    if ( empty( $password ) ) {
        return; 
    }

    // --- Helper: String Fonksiyonları (mbstring desteği yoksa fallback) ---
    
    // 1. Uzunluk Hesaplama
    if ( function_exists( 'mb_strlen' ) ) {
        $length = mb_strlen( $password );
    } else {
        $length = strlen( $password );
    }

    // 2. Küçük Harfe Çevirme
    $password_lower = function_exists( 'mb_strtolower' ) ? mb_strtolower( $password ) : strtolower( $password );
    $username_lower = function_exists( 'mb_strtolower' ) ? mb_strtolower( $username ) : strtolower( $username );
    
    // 3. String İçinde Arama (strpos wrapper)
    $str_contains = function( $haystack, $needle ) {
        if ( empty( $needle ) ) return false;
        if ( function_exists( 'mb_strpos' ) ) {
            return mb_strpos( $haystack, $needle ) !== false;
        }
        return strpos( $haystack, $needle ) !== false;
    };

    // ---------------------------------------------------------------------

    // 1. Minimum 12 karakter
    if ( $length < 12 ) {
        $errors->add( 'password_too_short', __( 'Şifre en az 12 karakter olmalıdır.', 'text-domain' ) );
    }

    // 2. Büyük Harf Kontrolü (Unicode uyumlu)
    if ( ! preg_match( '/\p{Lu}/u', $password ) ) {
        $errors->add( 'password_no_uppercase', __( 'Şifre en az bir büyük harf içermelidir.', 'text-domain' ) );
    }

    // 3. Küçük Harf Kontrolü (Unicode uyumlu)
    if ( ! preg_match( '/\p{Ll}/u', $password ) ) {
        $errors->add( 'password_no_lowercase', __( 'Şifre en az bir küçük harf içermelidir.', 'text-domain' ) );
    }

    // 4. Rakam Kontrolü
    if ( ! preg_match( '/[0-9]/', $password ) ) {
        $errors->add( 'password_no_number', __( 'Şifre en az bir rakam içermelidir.', 'text-domain' ) );
    }

    // 5. Özel Karakter Kontrolü
    if ( ! preg_match( '/[^\p{L}\p{N}]/u', $password ) ) { 
        $errors->add( 'password_no_special', __( 'Şifre en az bir özel karakter (örn: ! @ # $ % *) içermelidir.', 'text-domain' ) );
    }

    // 6. Şifre Kullanıcı Adını İçermemelidir
    if ( ! empty( $username ) ) {
        if ( $str_contains( $password_lower, $username_lower ) ) {
            $errors->add( 'password_contains_username', __( 'Şifre kullanıcı adınızı içermemelidir.', 'text-domain' ) );
        }
    }

    // 7. Şifre E-posta "Kullanıcı Adını" (Local Part) İçermemelidir
    if ( ! empty( $email ) ) {
        $email_parts = explode( '@', $email );
        $local_part  = isset( $email_parts[0] ) ? $email_parts[0] : '';
        
        // Local part'ı da küçültelim
        $local_part_lower = function_exists( 'mb_strtolower' ) ? mb_strtolower( $local_part ) : strtolower( $local_part );
        $local_part_len   = function_exists( 'mb_strlen' ) ? mb_strlen( $local_part ) : strlen( $local_part );

        if ( ! empty( $local_part ) && $local_part_len > 3 ) {
            if ( $str_contains( $password_lower, $local_part_lower ) ) {
                $errors->add( 'password_contains_email', __( 'Şifre e-posta adresinizin giriş kısmını içermemelidir.', 'text-domain' ) );
            }
        }
    }
}

/**
 * 1️⃣ Mevcut Kullanıcı Profil Güncellemesi (FILTER)
 */
add_filter( 'user_profile_update_errors', function( $errors, $update, $user ) {
    
    if ( isset( $_POST['pass1'] ) && !empty( $_POST['pass1'] ) ) {
        $password = wp_unslash( $_POST['pass1'] );
        $form_email = isset( $_POST['email'] ) ? $_POST['email'] : $user->user_email;
        
        enforce_strong_password_policy( $errors, $password, $user->user_login, $form_email );
    }
    
    return $errors; 

}, 10, 3 );


/**
 * 2️⃣ Şifre Sıfırlama (ACTION)
 */
add_action( 'validate_password_reset', function( $errors, $user ) {

    if ( isset( $_POST['pass1'] ) && !empty( $_POST['pass1'] ) ) {
        $password = wp_unslash( $_POST['pass1'] );
        enforce_strong_password_policy( $errors, $password, $user->user_login, $user->user_email );
    }

}, 10, 2 );


/**
 * 3️⃣ Yeni Üye Kaydı (FILTER)
 */
add_filter( 'registration_errors', function( $errors, $sanitized_user_login, $user_email ) {

    if ( isset( $_POST['pass1'] ) && !empty( $_POST['pass1'] ) ) {
        $password = wp_unslash( $_POST['pass1'] );
        enforce_strong_password_policy( $errors, $password, $sanitized_user_login, $user_email );
    }

    return $errors; 

}, 10, 3 );


/**
 * 4️⃣ Şifre İpucu Metnini Değiştirme
 */
add_filter( 'password_hint', function( $hint ) {
    return __( 'Şifre en az 12 karakter olmalı; büyük harf, küçük harf, rakam ve özel karakter içermelidir.', 'text-domain' );
} );