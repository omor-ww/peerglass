import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const htmlPath = resolve(root, 'dist/index.html');
let html = await readFile(htmlPath, 'utf8');
const jsPath = html.match(/<script[^>]+src="([^"]+\.js)"/i)?.[1];
const cssPath = html.match(/<link[^>]+href="([^"]+\.css)"/i)?.[1];
if (!jsPath || !cssPath) throw new Error('Could not find the built game assets. Run npm run build first.');
let js = await readFile(resolve(root, 'dist', jsPath.replace(/^\//, '')), 'utf8');
const css = await readFile(resolve(root, 'dist', cssPath.replace(/^\//, '')), 'utf8');
js = js.replace(/<\/script/gi, '<\\/script');
html = html
  .replace(/\s*<link rel="preconnect" href="https:\/\/fonts\.googleapis\.com">/g, '')
  .replace(/\s*<link href="https:\/\/fonts\.googleapis\.com[^"]*" rel="stylesheet">/g, '')
  .replace(/<script[^>]+src="[^"]+\.js"[^>]*><\/script>/i, `<script type="module">\n${js}\n</script>`)
  .replace(/<link[^>]+href="[^"]+\.css"[^>]*>/i, `<style>\n${css}\n</style>`)
  .replace('</title>', '</title>\n  <meta name="description" content="The Infinite Grimoire — single-file playable fantasy RPG">');
await writeFile(resolve(root, 'play.html'), html);
console.log('Created game/play.html — open this single HTML file in a modern browser to play.');
