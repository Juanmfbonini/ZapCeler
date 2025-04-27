document.addEventListener('DOMContentLoaded', function () {
  const clientesSelect = document.getElementById('clientes');

  if (clientesSelect) {
    new Choices(clientesSelect, {
      shouldSort: false,             // <-- mantém a ordem original
      removeItemButton: true,
      searchEnabled: true,
      placeholderValue: 'Selecione os Clientes...',
      noResultsText: 'Nenhum cliente encontrado',
      itemSelectText: '',
      position: 'bottom',
    });
  }
});
