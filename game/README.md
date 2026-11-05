# The Infinite Grimoire — playable prototype

A browser-playable 2.5D fantasy RPG prototype built with Three.js. It is a self-contained game alongside the existing PeerGlass Python project.

## Run it

```bash
cd game
npm install
npm run dev
```

Open the Vite URL in a WebGL-capable browser. Production build: `npm run build`.

## Controls

- **WASD / arrow keys:** move; **Shift:** run
- **Drag / swipe:** orbit the follow camera
- **Space:** cast the selected spell; **E:** interact; **B:** open the Grimoire; **M:** map; **Q:** dodge
- **Touch:** left virtual stick to move; right-side buttons cast, dodge and open the book
- **Book:** choose from all 60 spell entries, inspect the illustrated and detail pages, then select. The selected spell stays active after closing the book.
- **Voice:** use **Enable Mic** from the book/settings to grant browser microphone permission; say the selected spell's name. Speech input is browser-dependent, so touch and keyboard casting remain available.

## Implemented in this playable slice

- Perspective 3D terrain, a winding road, river, trees, rocks, an Oakridge outpost, a waystone and a loot chest.
- Pixel-art-style 2D billboard sprites for the player, villagers and enemies, with a following camera and basic world collision.
- Hostile creatures that pursue and attack, a merchant interaction, hit points, mana, XP/levels and summoned allies.
- 60 spellbook records with unique spell names, descriptions, costs and cooldowns; projectile, area, wall, storm, vortex, meteor, teleport, healing, shield, chain-lightning and summoning behaviors share combat/damage systems.
- Spell index, two-page presentation, world chart, minimap, quest journal, inventory, quality selector and local autosave.
- Responsive touch controls and browser speech recognition where supported.

This is an early playable vertical slice, not the complete ten-region open-world RPG described in the broader design brief. Assets and NPC/quest content are procedural placeholders; region streaming, full directional animation sets, authored dialogue/quest campaigns, real audio, production-grade spell-specific art, and native Android packaging remain future work. The game does not claim voice input is available when the current browser lacks speech recognition.
