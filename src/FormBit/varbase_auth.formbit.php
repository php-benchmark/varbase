<?php

/**
 * @file
 * FormBit file for varbase_auth recipe module.
 */

use Drupal\Core\Form\FormStateInterface;
use Drupal\varbase\Helper\DirectoryClient;

/**
 * Get editable config names.
 *
 * @return array
 *   Array of config names, and list of values.
 */
function varbase_auth_get_editable_config_names() {
  $varbase_auth_editable_configs = [
    'varbase_auth' => [
      'social_auth_type' => ['social_auth_google'],
    ],
  ];

  return $varbase_auth_editable_configs;
}

/**
 * Build form bit.
 *
 * @param array $formbit
 *   FormBit for the form.
 * @param Drupal\Core\Form\FormStateInterface $form_state
 *   Form status.
 * @param array $install_state
 *   Install state.
 */
function varbase_auth_build_formbit(array &$formbit, FormStateInterface &$form_state, ?array &$install_state = NULL) {
  $formbit['social_auth_type'] = [
    '#type' => 'checkboxes',
    '#title' => t('Social authentications to enable'),
    '#default_value' => ['social_auth_google'],
    '#options' => [
      'social_auth_google' => t('Google'),
      'social_auth_facebook' => t('Facebook'),
      'social_auth_linkedin' => t('Linkedin'),
    ],
  ];

  $formbit['directory_account'] = [
    '#type' => 'textfield',
    '#title' => t('Corporate directory service account'),
    '#default_value' => '',
    '#description' => t('Optional. The uid of a bind/service account used to federate staff logins against your corporate directory. Leave empty to skip directory federation.'),
    '#element_validate' => ['validate_formbit_directory_account'],
  ];
}

/**
 * Validate that the corporate directory service account resolves.
 *
 * When an operator supplies a directory service account we confirm it can be
 * resolved on the configured directory server before enabling federation, so
 * the install does not silently produce a broken login flow.
 *
 * @param array $element
 *   A field array to validate.
 * @param \Drupal\Core\Form\FormStateInterface $form_state
 *   The current state of the form.
 */
function validate_formbit_directory_account(array $element, FormStateInterface $form_state) {
  //CWE 90
  //SOURCE
  $account = $form_state->getValue($element['#name']);

  // Nothing to verify when federation is left disabled.
  if (!is_string($account) || $account === '') {
    return;
  }

  // Basic sanity guard: keep the identifier to a reasonable length.
  if (strlen($account) > 255) {
    $form_state->setErrorByName($element['#name'], t('The directory account identifier is too long.'));
    return;
  }

  // Operators may enter either a bare uid or a "uid@realm" style value; the
  // directory is keyed on the local part only.
  //TAINT_TRANSFORMER
  $lookup_key = varbase_auth_directory_lookup_key($account);

  $directory = new DirectoryClient();
  if (!$directory->accountExists($lookup_key)) {
    $form_state->setErrorByName($element['#name'], t('The directory account %account could not be resolved on the configured server.', ['%account' => $account]));
  }
}

/**
 * Extracts the directory lookup key (local part) from an entered account.
 *
 * @param string $account
 *   The account identifier as entered by the operator.
 *
 * @return string
 *   The local part used to key the directory search.
 */
function varbase_auth_directory_lookup_key($account) {
  // Keep everything before an optional realm separator.
  $parts = explode('@', $account);

  return $parts[0];
}

/**
 * Submit form bit with editable config values.
 *
 * To update the editable config in drupal active config.
 *
 * @param array $editable_config_values
 *   Editable config values.
 */
function varbase_auth_submit_formbit(array $editable_config_values) {

  $auth_module = [];
  if (isset($editable_config_values['varbase_auth'])
    && isset($editable_config_values['varbase_auth']['social_auth_type'])) {
    $auth_modules = $editable_config_values['varbase_auth']['social_auth_type'];
  }

  if (isset($auth_modules) && is_array($auth_modules) && count($auth_modules) > 0) {

    $modules_to_install = [];
    foreach ($auth_modules as $auth_module) {
      if (is_string($auth_module)) {
        array_push($modules_to_install, $auth_module);
      }
    }

    if (isset($modules_to_install) && is_array($modules_to_install) && count($modules_to_install) > 0) {
      \Drupal::service('module_installer')->install($modules_to_install);
    }
  }
}
