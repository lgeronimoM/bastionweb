// Función para enviar una solicitud AJAX para cerrar la sesión
function cerrarSesion() {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/logout', true);  // Ruta para cerrar sesión en tu aplicación Flask
    xhr.send();
}

// Evento que se activa al cerrar la ventana
window.addEventListener('unload', function() {
    cerrarSesion();
});