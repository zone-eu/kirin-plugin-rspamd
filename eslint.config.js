'use strict';

const { defineConfig } = require('eslint/config');
const { builtinRules } = require('eslint/use-at-your-own-risk');
const nodemailer = require('eslint-config-nodemailer');
const prettier = require('eslint-config-prettier/flat');

const recommendedRules = Object.fromEntries(
    Array.from(builtinRules)
        .filter(([, rule]) => rule.meta && rule.meta.docs && rule.meta.docs.recommended)
        .map(([ruleId]) => [ruleId, 'error'])
);

module.exports = defineConfig([
    {
        ignores: ['node_modules/**'],
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: 'commonjs',
            globals: {
                Buffer: 'readonly',
                clearTimeout: 'readonly',
                console: 'readonly',
                module: 'readonly',
                process: 'readonly',
                require: 'readonly',
                setTimeout: 'readonly'
            }
        },
        rules: {
            ...recommendedRules,
            ...nodemailer.rules
        }
    },
    prettier,
    {
        rules: {
            indent: 0,
            'no-prototype-builtins': 0
        }
    }
]);
