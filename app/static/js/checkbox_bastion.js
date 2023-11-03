$(function () {
    $("#chkPassport").click(function () {
      if ($(this).is(":checked")) {
        $("#dvPassport").show();
        $("#AddPassport").hide();
      } else {
        $("#dvPassport").hide();
        $("#AddPassport").show();
      }
    });
  });

  //Add a JQuery click event handler onto our checkbox.
  $('#terms_and_conditions').click(function(){
    //If the checkbox is checked.
    if($(this).is(':checked')){
      //Enable the submit button.
      $('#submit_button').attr("disabled", false);
    } else{
      //If it is not checked, disable the button.
      $('#submit_button').attr("disabled", true);
    }
  });

  function habilitarBotones() {
    var checkboxes = document.querySelectorAll('#activeEditor');
    var botones = document.querySelectorAll('#regenAvalive');

    var alMenosUnCheckboxSeleccionado = false;

    checkboxes.forEach(function(checkbox) {
      if (checkbox.checked) {
        alMenosUnCheckboxSeleccionado = true;
      }
    });

    botones.forEach(function(boton) {
      boton.disabled = !alMenosUnCheckboxSeleccionado;
    });
  }