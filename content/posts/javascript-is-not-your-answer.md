---
title : 'Javascript Is Not The Answer'
date : 2024-10-16T22:30:06-05:30
draft : false
tags : ["javascript", "rant"]
---


During the last three weeks, javascript has been the reason for all of my misery.
The more javascript i write, the more i wonder 'Who put this piece of shit on the server!'
Even though it has always given me problems, there's two problems that made me (almost) physically abuse my keyboard.

No, i won't be talking about what `{} - []` results in, why spend time thinking about things that you will never use?

## 'Cross platform' is a joke

Consider the following snippets

```js
import { App } from './app'
```

```js
import { App } from './App'
```

Both of the code snippets work perfectly fine, as long as you are on windows. But on any other (real) OS, it is not the case.
The reason is windows has a **case insensitive file system**. And no, Typescript won't save you this time.

'Yea, yea, it is the PRogRAmmErS rEsPoNSiBlItY' I hear you, but shouldn't the language flag this as an illegal import? This is no surprise, because javascript was designed only with light scripting in mind and was designed to fail. Putting it on the server next to our databases is our mistake.

This is something that i have tested on NodeJS, but i don't expect other runtimes to behave any differently - at the end of the day, why test code in a language that stinks. Just avoid javascript at all costs.

## Lack of a type system

Not every language requires a strong type system - imagine writing types in bash.

But when you have to write mission critical code, a type system is very useful. I won't talk about how a good type system makes illegal states irrepresentable, [Tris is way better at it.](https://www.youtube.com/watch?v=z-0-bbc80JM). Instead, i will be focusing on something which you get for free from a type system - autocomplete, or as you vscode nerds may know it, Intellisense.

By having strong types, you can convey more context and information not only to your text-edtitor, but also your peers. Good types are the best docuementation because they are not external to code, they are part of the code itself

![Intellisense in action](/posts/javascript-is-not-your-answer.md/nvim-cmp.png)
