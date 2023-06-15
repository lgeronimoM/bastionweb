document.addEventListener('DOMContentLoaded', function() {
  var logButton = document.getElementById('logButton');
  var logModal = document.getElementById('logModal');
  var logContent = document.getElementById('log-content');

  logButton.addEventListener('click', function() {
      fetch('/get_log')
          .then(response => response.json())
          .then(data => {
              logContent.textContent = data.log;
              var instance = M.Modal.getInstance(logModal);
              instance.open();
          })
          .catch(error => {
              console.error('Error al obtener el log:', error);
          });
  });

  var closeButton = document.getElementById('closeButton');
  closeButton.addEventListener('click', function() {
      var instance = M.Modal.getInstance(logModal);
      instance.close();
  });
});
