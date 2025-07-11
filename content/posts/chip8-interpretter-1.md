---
title : 'Chip8 Interpretter 1'
date : 2024-12-17T00:35:46+05:30
draft : false
tags:
- C
- Rust
- ChatGPT
- Emulation
---

Out of the blue, after my SIH victory, i decided to give web development and cybersecurity a little break and decided to write a chip8 emulator.
This is one project that i have always been wanting to do for quite a long time, but never got free enough to do it.

<!--more-->

## Libraries

For this project, i am using only one dependency (well, atleast for now) - to handle the graphics and audio side of the interpretter. It is a super cool library called raylib. I did this so that i can focus on writing an interpretter, rather than writing a renderer. 

## Implementation

On the first day, in just a few minutes, I got quite far with the basic boilerplate setup - thanks to cmake.

Now, onto implementing the chip8 interpretter.

I defined the state of the chip8 interpretter as a struct 

```C
typedef uint8_t u8;
typedef uint16_t u16;
typedef  uint8_t r8 ;
typedef  uint16_t r16 ;

typedef struct {
    u8 memory[0xFFF];
    r8 V[16];

    r16 I;
    r8 Delay, Sound;

    // private registers
    r16 PC;
    r8 SP;

    r16 stack[16];
    u8  framebuffer[32][64];
} Chip8_State ;
```

The idea is 
- I fetch an opcode from the chip8's ram
- I find the corresponding instruction for it.
- I execute the instruction and make change to the state.
- I render the framebuffer of the modified state.

## The renderer

### AI ain't taking my job away

I decided to implement the renderer first, as i felt it would be the most pain in the ass. I tried to ChatGPT the code, but i was met with dissapointment.
```C
// Function to render CHIP-8 VRAM to the screen
void RenderChip8Display(const VRam_t VRam) {
    for (int y = 0; y < CHIP8_HEIGHT; y++) {
        for (int x = 0; x < CHIP8_WIDTH; x++) {
            if (VRam[y * CHIP8_WIDTH + x]) {
                // Draw a filled rectangle for each active pixel
                DrawRectangle(x * PIXEL_SIZE, y * PIXEL_SIZE, PIXEL_SIZE, PIXEL_SIZE, WHITE);
            }
        }
    }
}
```

Dude was literally drawing each square of the chip8 display individually.

### Handmade naive implementation

Outraged by the AI generated piece of despair and with the motivation that i won't lose my future job to AI anytime soon, I started writing my own renderer.

The idea for this renderer is super simple:
- I read the chip8's framebuffer, and map it to an image.
- I scale the image according to the pixel size.
- I make a texture from the image, and put it on the screen

This was a pretty naive method caused due to my skill issues with raylib. I realised it was a very bad idea when raylib created a gpu texture every single frame.

### Better batched alternative

After reading the `raylib.h` header file for some time, i stumbled upon two interesting functions:
- `RLAPI void UpdateTexture(Texture2D texture, const void *pixels);`
- `void DrawTextureEx(Texture2D texture, Vector2 position, float rotation, float scale, Color tint);`

I decided to upgrade my rendering algorithm with these new steps:
- I update the texture every frame with my new framebuffer.
- I draw the texture to the window, but scale it PIXEL_SIZE times.

This gave me quite satisfactory results, and i decided to move on to the opcode interprettation part.

```C
void RenderFramebuffer(u8 framebuffer[32][64], Texture2D tex) {
    UpdateTexture(tex, framebuffer);
    DrawTextureEx(tex, (Vector2){.x = 0.0, .y = 0.0}, 0.0, PIXEL_SIZE, WHITE);
}
```

<video src="/posts/vid.mp4" />

## The Interpretter

Implementing the interpretter turned out to be a mind-bending excercise. The fact that chip8 used little-endian byte ordering messed up with my mind to such an extent that i was not able to think straight for a few hours.

### Endian trouble

Chip8 uses little-endian notation, ie the most significant byte in a multi-byte number (like u16) comes on the leftmost part and the least significant byte comes on the right most part.

Hence, the code for extracting an opcode from ram looked something like this:
```C

typedef  union {
    u16 full;
    struct  {
        u8 high;
        u8 low;
    };
} instruction;

instruction i;
i.high = state.memory[state.PC];
i.low = state.memory[state.PC + 1];
state.PC += 2;
```

For some reason, the high byte and low byte were in reverse order. I spent 45 long minutes debugging this, only to realise the order high and low bytes in the instruction definition are different. 🥴🥴🥴

```C
typedef  union {
    u16 full;
    struct  {
        u8 low;
        u8 high;
    };
} instruction;
```

After fixing that, i decided to call it a day and retire.
