/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        iron: {
          950: "#161110",
          900: "#1d1714",
          800: "#291f1a",
          700: "#3a2c24",
          600: "#4d3b30",
        },
        ash: {
          400: "#a89a8c",
          300: "#c2b6a9",
        },
        parchment: {
          100: "#f4ead9",
        },
        ember: {
          600: "#d4501f",
          500: "#ff6a34",
          400: "#ff8f5c",
        },
        temper: {
          500: "#3f938c",
          400: "#5fb3ac",
          300: "#8ccec8",
        },
        rust: {
          500: "#c1443a",
          400: "#dd6459",
        },
      },
      fontFamily: {
        display: ['"Big Shoulders Display"', "sans-serif"],
        serif: ['"Source Serif 4"', "serif"],
        mono: ['"IBM Plex Mono"', "monospace"],
      },
    },
  },
  plugins: [],
};
