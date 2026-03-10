import { updateVisitCounter } from './visit-counter.js';
import { loadControversialGallery } from './controversial-carousel.js';
import { getCurrentUser } from './supabase-client.js';

document.addEventListener('DOMContentLoaded', async () => {
  // Actualizar contador de visitas
  await updateVisitCounter();
  
  // Cargar galería controversial
  await loadControversialGallery();
  
  // Verificar sesión
  const user = await getCurrentUser();
  if (user) {
    console.log('Usuario autenticado:', user.email);
    updateUIForLoggedInUser(user);
  }
});

function updateUIForLoggedInUser(user) {
  // Mostrar botón de logout, panel de admin, etc.
  const authContainer = document.getElementById('auth-container');
  if (authContainer) {
    authContainer.innerHTML = `
      <p>Bienvenida, ${user.email}</p>
      <button id="logout-btn">Cerrar sesión</button>
    `;
    document.getElementById('logout-btn')?.addEventListener('click', async () => {
      const { signOut } = await import('./supabase-client.js');
      await signOut();
      window.location.reload();
    });
  }
}
