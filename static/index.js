document.addEventListener('DOMContentLoaded', function () {
  const clientesSelect = document.getElementById('clientes');
  const testButton = document.querySelector('.btn-test');

  if (clientesSelect) {
    new Choices(clientesSelect, {
      shouldSort: false,
      removeItemButton: true,
      searchEnabled: true,
      placeholderValue: 'Selecione os Clientes...',
      noResultsText: 'Nenhum cliente encontrado',
      itemSelectText: '',
      position: 'bottom',
    });
  }

  // Verifica se o botão de teste existe e se o usuário já usou o teste
  if (testButton) {
    // Esta verificação deveria ser feita no servidor, mas como exemplo:
    // Você pode adicionar uma classe 'used-test' ao botão no template quando o teste já foi usado
    if (testButton.classList.contains('used-test')) {
      testButton.textContent = 'O TESTE JÁ FOI ENCERRADO';
      testButton.disabled = true;
      testButton.style.backgroundColor = '#cccccc';
      testButton.style.cursor = 'not-allowed';
    }
  }

  // Prevent double submission
  document.querySelectorAll('form').forEach(form => {
    form.addEventListener('submit', function(e) {
        const button = this.querySelector('button');
        button.disabled = true;
        button.innerHTML = '<span class="spinner"></span> Processando...';
        
        setTimeout(() => {
            if (!this.submitted) {
                button.disabled = false;
                button.innerHTML = 'Tentar Novamente';
                this.submitted = true;
            }
        }, 5000);
    });
  });
});

// Verificação de código - foco automático e validação
const verificationCodeInput = document.getElementById('verification_code');
if (verificationCodeInput) {
    verificationCodeInput.focus();
    
    verificationCodeInput.addEventListener('input', function() {
        this.value = this.value.replace(/[^0-9]/g, '');
        if (this.value.length === 6) {
            this.form.submit();
        }
    });
}

// Animações dos cards de onboarding
document.querySelectorAll('.step-card').forEach(card => {
    card.addEventListener('mouseenter', function() {
        this.style.transform = 'translateY(-5px)';
    });
    
    card.addEventListener('mouseleave', function() {
        this.style.transform = '';
    });
});

// Atualização dinâmica do progresso
const progressBar = document.querySelector('.progress-bar');
if (progressBar) {
    // Animação suave da barra de progresso
    const targetWidth = progressBar.style.width;
    progressBar.style.width = '0';
    
    setTimeout(() => {
        progressBar.style.transition = 'width 1s ease';
        progressBar.style.width = targetWidth;
    }, 300);
}

document.addEventListener('DOMContentLoaded', function() {
    // Foco automático no campo de código
    const codeInput = document.getElementById('verification_code');
    if (codeInput) {
        codeInput.focus();
        
        // Validação em tempo real
        codeInput.addEventListener('input', function() {
            this.value = this.value.replace(/\D/g, '').slice(0, 6);
        });
    }
    
    // Reenvio de código
    const resendBtn = document.getElementById('resend-code');
    if (resendBtn) {
        resendBtn.addEventListener('click', function() {
            this.disabled = true;
            this.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Enviando...';
            
            fetch("{{ url_for('reenviar_codigo') }}", {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    phone_number: "{{ phone_number }}"
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('Código reenviado com sucesso!');
                } else {
                    alert('Erro: ' + (data.error || 'Falha no reenvio'));
                }
            })
            .catch(() => alert('Erro de conexão'))
            .finally(() => {
                this.disabled = false;
                this.textContent = 'Reenviar Código';
            });
        });
    }
});

document.getElementById('opcoes_numeros').addEventListener('change', function() {
        this.form.submit();
    });