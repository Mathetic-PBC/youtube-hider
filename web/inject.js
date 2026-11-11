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
