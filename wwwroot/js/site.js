﻿//JavaScript para la página de Personal
var isEditing = false;
function toggleEdit(id) {
    var rolText = document.getElementById('rol-text-' + id);
    var rolForm = document.getElementById('rol-form-' + id);
    if (rolText.classList.contains('hidden')) {
        rolText.classList.remove('hidden');
        rolForm.classList.add('hidden');
        isEditing = false;
    } else {
        rolText.classList.add('hidden');
        rolForm.classList.remove('hidden');
        isEditing = true;
    }
}

function submitForm(id) {
    var form = document.getElementById('rol-form-' + id);
    form.submit();
}

document.addEventListener('click', function (event) {
    var isClickInside = false;
    var forms = document.querySelectorAll('form[id^="rol-form-"]');
    forms.forEach(function (form) {
        if (form.contains(event.target) || event.target.closest('button[onclick^="toggleEdit"]')) {
            isClickInside = true;
        }
    });

    if (!isClickInside && isEditing) {
        location.reload(); // Refrescar la página para cancelar la edición
    }
});
// Manejar envío del formulario de reactivación
document.querySelectorAll('form[asp-action="ReactivateEmployee"]').forEach(form => {
    form.addEventListener('submit', function (e) {
        e.preventDefault();

        fetch(this.action, {
            method: 'POST',
            body: new FormData(this)
        }).then(response => {
            if (response.ok) {
                location.reload(); // Recargar para ver cambios
            }
        });
    });
});
document.addEventListener('DOMContentLoaded', function () {
    const filterForm = document.getElementById('filterForm');

    if (filterForm) {
        filterForm.addEventListener('submit', function (e) {
            const checkboxes = Array.from(this.querySelectorAll('input[name="estados"]:checked'));

            // Si no hay checkboxes marcados, forzar "Activo"
            if (checkboxes.length === 0) {
                e.preventDefault();
                const activoCheckbox = this.querySelector('input[name="estados"][value="Activo"]');
                activoCheckbox.checked = true;
                this.submit();
            }
        });
    }
});
function filterTable() {
    var input, filter, table, tr, td, i, j, txtValue;
    input = document.getElementById("simple-search");
    filter = input.value.toUpperCase();
    table = document.querySelector("table");
    tr = table.getElementsByTagName("tr");

    for (i = 1; i < tr.length; i++) {
        tr[i].style.display = "none";
        td = tr[i].getElementsByTagName("td");
        for (j = 0; j < td.length; j++) {
            if (td[j]) {
                txtValue = td[j].textContent || td[j].innerText;
                if (txtValue.toUpperCase().indexOf(filter) > -1) {
                    tr[i].style.display = "";
                    break;
                }
            }
        }
    }
}
