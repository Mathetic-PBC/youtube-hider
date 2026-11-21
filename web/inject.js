// youtube-hider: when the proxy refuses an in-page request it names the page
// to load instead. Following it is a courtesy; the refusal already happened.
(() => {
  const HEADER = 'x-hider-goto';
  const go = (to) => { if (to) location.assign(to); };
  const nativeFetch = window.fetch;
  window.fetch = function (...args) {
    return nativeFetch.apply(this, args).then((res) => {
      go(res.headers.get(HEADER));
      return res;
    });
  };
  const nativeSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function (...args) {
    this.addEventListener('load', () => {
      try { go(this.getResponseHeader(HEADER)); } catch (_) {}
    });
    return nativeSend.apply(this, args);
  };
})();

// youtube-hider: ads. The proxy strips ad schedules from player data before
// the page sees them, so normally there is nothing to do here. These two
// cover what that cannot reach.
(() => {
  // Some player versions hold playback on a 17-second timer when the ads
  // they expected are missing. Run that one timer immediately.
  const nativeSetTimeout = window.setTimeout;
  window.setTimeout = function (fn, delay, ...rest) {
    if (delay === 17000 && typeof fn === 'function' && String(fn).includes('[native code]')) delay = 17;
    return nativeSetTimeout.call(this, fn, delay, ...rest);
  };

  // An ad stitched into the stream by the server has no schedule to strip.
  // If the player reports it is showing one, mute it, jump to its end, and
  // press skip.
  const dismiss = () => {
    const player = document.getElementById('movie_player');
    if (!player || !player.classList.contains('ad-showing')) return;
    const video = player.querySelector('video');
    if (video && Number.isFinite(video.duration) && video.currentTime < video.duration - 0.2) {
      video.muted = true;
      video.currentTime = video.duration;
    }
    player.querySelector('.ytp-skip-ad-button, .ytp-ad-skip-button, .ytp-ad-skip-button-modern')?.click();
  };
  nativeSetTimeout(function watch() {
    const player = document.getElementById('movie_player');
    if (!player) return nativeSetTimeout(watch, 500);
    new MutationObserver(dismiss).observe(player, { attributes: true, attributeFilter: ['class'] });
    setInterval(dismiss, 500);
    dismiss();
  }, 500);
})();
