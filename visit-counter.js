import { supabase } from './supabase-client.js';

export async function incrementVisit() {
  const { error } = await supabase
    .from('visits')
    .insert({
      ip_hash: await getIPHash(),
      user_agent: navigator.userAgent
    });
  
  if (error) console.error('Error counting visit:', error);
}

export async function getVisitCount() {
  const { count, error } = await supabase
    .from('visits')
    .select('*', { count: 'exact', head: true });
  
  if (error) {
    console.error('Error getting count:', error);
    return 0;
  }
  return count;
}

async function getIPHash() {
  // Simple hash del user agent + timestamp para privacidad
  const str = navigator.userAgent + new Date().toDateString();
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return hash.toString(16);
}

export async function updateVisitCounter() {
  await incrementVisit();
  const count = await getVisitCount();
  
  const counterElement = document.getElementById('visit-counter');
  if (counterElement) {
    const formatted = String(count).padStart(3, '0');
    counterElement.textContent = `$visitas_contador: [${formatted}]`;
  }
}
