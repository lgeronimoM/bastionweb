// modal para contenido del log

document.addEventListener('DOMContentLoaded', function() {
    var logButton = document.getElementById('logButton');
    var logModal = document.getElementById('logModal');
    var logContent = document.getElementById('log-content');
    var closeButton = document.getElementById('closeButton');

    // Inicializar el modal
    var modalInstance = M.Modal.init(logModal, {});

    // Agregar evento click al botón para mostrar el modal
    logButton.addEventListener('click', function() {
      // Hacer la solicitud al servidor para obtener el log
      fetch('/get_log')
        .then(response => response.text())
        .then(data => {
          // Colocar el contenido del log en el elemento pre dentro del modal
          logContent.textContent = data;

          // Abrir el modal
          modalInstance.open();
        })
        .catch(error => {
          console.error('Error al obtener el log:', error);
        });
    });

    // Agregar evento click al botón de cerrar modal
    closeButton.addEventListener('click', function() {
      // Cerrar el modal
      modalInstance.close();
    });
}); 

// modal para loading

document.addEventListener('DOMContentLoaded', function() {
    var modal = document.getElementById("miModal");
    var instance = M.Modal.init(modal, {dismissible: false});

    window.mostrarPreload = function() {
      deshabilitarModal();
      instance.open();
    };

    window.habilitarModal = function() {
      instance.options.dismissible = true;
      modal.style.pointerEvents = "auto";
    };

    window.deshabilitarModal = function() {
      instance.options.dismissible = false;
      modal.style.pointerEvents = "none";
    };

    // Inicializar el modal al cargar el contenido
    var elems = document.querySelectorAll('.modal');
    var instances = M.Modal.init(elems);
  });