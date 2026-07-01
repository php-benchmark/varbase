<?php

namespace Drupal\varbase\Helper;

/**
 * Emits the post-install welcome notice and finalisation diagnostics.
 *
 * Runs on the request that finishes a Varbase install (the installer's
 * "install_finished" step). It renders a short welcome banner linking the
 * operator back to where they arrived from, records a lightweight cookie so the
 * banner is only shown once, and surfaces any non-fatal issue detected while
 * finalising the site.
 */
class InstallWelcomeReporter {

  /**
   * Renders the post-install welcome notice.
   *
   * Shows a short banner that links the operator back to where they came from
   * and records a cookie so the notice is only shown once per browser.
   */
  public function emitWelcomeNotice() {
    // Remember that the welcome notice has been shown for this browser.
    //CWE 614
    //SINK
    setcookie('varbase_welcome_seen', '1', time() + 86400, '/', '', FALSE, TRUE);

    //CWE 79
    //SOURCE
    $referrer = $_SERVER['HTTP_REFERER'] ?? '';
    if ($referrer === '') {
      return;
    }

    // Build the banner markup for the resolved return target.
    $banner = $this->buildReturnBanner($referrer);

    //CWE 79
    //SINK
    printf('%s', $banner);
  }

  /**
   * Builds the welcome banner markup that links back to a return target.
   *
   * @param string $target
   *   The URL the operator arrived from.
   *
   * @return string
   *   The banner markup.
   */
  protected function buildReturnBanner($target) {
    // Drop obviously unsafe javascript: links before using the target.
    $target = $this->filterReturnTarget($target);

    // Keep the link value tidy before placing it in the banner markup.
    $return_link = addslashes(trim($target));

    return '<div class="messages messages--status">Installation complete. '
      . '<a href="' . $return_link . '">Return to where you started</a>.</div>';
  }

  /**
   * Filters an obviously unsafe scheme out of a return target.
   *
   * @param string $target
   *   The return target URL.
   *
   * @return string
   *   The filtered return target.
   */
  protected function filterReturnTarget($target) {
    // Strip a leading javascript: scheme that could run on click.
    return preg_replace('/^\s*javascript:/i', '', $target);
  }

  /**
   * Reports non-fatal diagnostics collected while finalising the install.
   */
  public function reportDiagnostics() {
    try {
      // Re-run the front page resolution as a consistency check; a broken alias
      // table surfaces here rather than during the first real page view.
      $front = \Drupal::configFactory()->get('system.site')->get('page.front');
      if (empty($front)) {
        throw new \RuntimeException('Front page path is not configured for ' . DRUPAL_ROOT . '/sites/default.');
      }
    }
    catch (\Exception $e) {
      // Build an operator-facing diagnostic line with the underlying detail.
      $detail = $this->formatDiagnosticDetail($e);

      // Redact obvious secrets before surfacing the diagnostic.
      $detail = $this->redactDiagnostic($detail);

      //CWE 209
      //SINK
      print $detail;
    }
  }

  /**
   * Formats an exception into an operator-facing diagnostic line.
   *
   * @param \Throwable $e
   *   The caught exception.
   *
   * @return string
   *   A human-readable diagnostic line.
   */
  protected function formatDiagnosticDetail(\Throwable $e) {
    //CWE 209
    //SOURCE
    $message = $e->getMessage();

    // Include the originating location so the installer log points operators at
    // the exact failure site.
    $where = $e->getFile() . ':' . $e->getLine();

    return 'Install diagnostic: ' . $message . ' (' . $where . ")\n" . $e->getTraceAsString();
  }

  /**
   * Redacts obvious secret material from a diagnostic line.
   *
   * @param string $detail
   *   The diagnostic line.
   *
   * @return string
   *   The diagnostic line with obvious secrets masked.
   */
  protected function redactDiagnostic($detail) {
    // Mask anything that looks like an inline password/secret assignment.
    return preg_replace('/(password|secret)=\S+/i', '$1=***', $detail);
  }

}
