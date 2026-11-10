/**
 * Phish & Chips - Gmail add-on that scores how risky an opened email is.
 *
 * When an email is opened, the add-on sends it to our backend, which returns
 * a risk score (0-100), a verdict and the reasons. The add-on only displays.
 *
 * Configuration lives in Script Properties (Project Settings), never in code:
 *   BACKEND_URL  e.g. https://something.trycloudflare.com
 *   API_KEY      the same secret the backend was started with
 */

// Product name shown in the card header (also set "name" in appsscript.json)
var APP_NAME = 'Phish & Chips';
// Logo shown at the top of the card (docs/logo-card.png in the GitHub repository).
var LOGO_URL = 'https://raw.githubusercontent.com/libispivak/phish-and-chips/main/docs/logo-card.png';

// Plain-language wording for everyday users: what it means + what to do.
// Colors are Google's own palette so the card feels native to Gmail.
var VERDICT_STYLE = {
  safe: {
    label: 'Looks safe', icon: '✅', color: '#1E8E3E',
    advice: 'We found no signs of a scam. Still, be careful with any unexpected request for money or passwords.'
  },
  suspicious: {
    label: 'Be careful', icon: '⚠️', color: '#E37400',
    advice: 'Some things look unusual. If you were not expecting this email, check with the sender ' +
            'another way (phone, WhatsApp) before clicking links or opening files.'
  },
  malicious: {
    label: 'Likely a scam', icon: '🚨', color: '#D93025',
    advice: 'Do not click links, open attachments or reply. ' +
            'You can report it with Gmail\'s "Report phishing" option.'
  }
};

var GREY = '#5F6368';
var LIGHT_GREY = '#DADCE0';

/** Shown when the add-on is opened with no email selected. */
function onHomepage(e) {
  return simpleCard_('Open an email to analyze it.');
}

/** Runs every time the user opens an email (contextual trigger). */
function onGmailMessageOpen(e) {
  // The add-on may only read the message the user opened, using this token.
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  var message = GmailApp.getMessageById(e.gmail.messageId);

  var result;
  try {
    result = analyze_(message.getRawContent());
  } catch (err) {
    console.error('analysis failed: ' + err.message);   // no email content in logs
    return simpleCard_('Could not analyze this email right now. ' + err.message);
  }
  return buildResultCard_(result);
}

/** Sends the raw email to the backend and returns the parsed JSON result. */
function analyze_(rawContent) {
  var props = PropertiesService.getScriptProperties();
  // trim(): a key pasted from the terminal often carries an invisible space or newline
  var backendUrl = (props.getProperty('BACKEND_URL') || '').trim();
  var apiKey = (props.getProperty('API_KEY') || '').trim();
  if (!backendUrl || !apiKey) {
    throw new Error('The add-on is not configured (BACKEND_URL / API_KEY).');
  }

  var response = UrlFetchApp.fetch(backendUrl.replace(/\/+$/, '') + '/analyze', {
    method: 'post',
    contentType: 'application/json',
    headers: { 'X-API-Key': apiKey },
    payload: JSON.stringify({
      raw_base64: Utilities.base64Encode(rawContent, Utilities.Charset.UTF_8)
    }),
    muteHttpExceptions: true
  });

  var status = response.getResponseCode();
  if (status === 401) throw new Error('The backend rejected the API key.');
  if (status === 413) throw new Error('This email is too large to analyze.');
  if (status !== 200) throw new Error('The analysis service returned an error (' + status + ').');
  return JSON.parse(response.getContentText());
}

/** Builds the result card: verdict + meter, advice, reasons, and collapsible details. */
function buildResultCard_(result) {
  var style = VERDICT_STYLE[result.verdict] || VERDICT_STYLE.suspicious;
  var score = Math.max(0, Math.min(100, Number(result.score) || 0));
  var signals = result.signals || [];
  var isSafe = result.verdict === 'safe';

  // --- Verdict: big colored label + a 10-block meter that is readable at a glance
  var filled = Math.ceil(score / 10);
  var meter = '<font color="' + style.color + '">' + repeat_('■', filled) + '</font>' +
              '<font color="' + LIGHT_GREY + '">' + repeat_('■', 10 - filled) + '</font>';
  var verdict = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(
      '<font color="' + style.color + '"><b>' + style.icon + '  ' + style.label.toUpperCase() + '</b></font>'))
    .addWidget(CardService.newTextParagraph().setText(
      meter + '   <b>' + score + '</b><font color="' + GREY + '"> / 100 risk</font>'));

  // --- What to do
  var advice = CardService.newCardSection()
    .addWidget(heading_('💡 WHAT TO DO'))
    .addWidget(CardService.newTextParagraph().setText(isolate_(escapeHtml_(style.advice))));

  var card = CardService.newCardBuilder()
    .addSection(logoSection_())
    .addSection(verdict)
    .addSection(advice);

  // --- What we noticed (plain language). On a safe email: no warning icons,
  // reassuring heading (transparency without alert fatigue).
  if (signals.length) {
    var reasons = CardService.newCardSection()
      .addWidget(heading_(isSafe ? '🔍 SMALL THINGS WE NOTICED' : '🔍 WHAT WE NOTICED'));
    if (isSafe) {
      reasons.addWidget(CardService.newTextParagraph().setText(
        '<font color="' + GREY + '"><i>These are normal in many emails. Nothing to worry about.</i></font>'));
    }
    signals.forEach(function (signal) {
      var marker = isSafe ? '•' : (signal.strength === 'strong' ? '🔴' : '🟡');
      // Signal text contains pieces of the email (names, domains): untrusted, so escape it.
      reasons.addWidget(CardService.newTextParagraph().setText(
        marker + ' <b>' + isolate_(escapeHtml_(signal.title)) + '</b><br>' +
        '<font color="' + GREY + '">' + isolate_(escapeHtml_(signal.detail)) + '</font>'));
    });
    if (!isSafe) {
      reasons.addWidget(CardService.newTextParagraph().setText(
        '<font color="' + GREY + '">🔴 serious warning sign · 🟡 minor sign</font>'));
    }
    card.addSection(reasons);
  }

  // --- How the score works (collapsed)
  card.addSection(CardService.newCardSection()
    .setHeader('ℹ️ How the score works')
    .setCollapsible(true)
    .setNumUncollapsibleWidgets(0)
    .addWidget(CardService.newTextParagraph().setText(
      'The score goes from 0 (no warning signs) to 100 (many serious warning signs).<br>' +
      '<font color="' + VERDICT_STYLE.safe.color + '"><b>0–24</b> Looks safe</font><br>' +
      '<font color="' + VERDICT_STYLE.suspicious.color + '"><b>25–59</b> Be careful</font><br>' +
      '<font color="' + VERDICT_STYLE.malicious.color + '"><b>60–100</b> Likely a scam</font><br>' +
      '<font color="' + GREY + '">An email is marked a scam when it lies about who sent it or where ' +
      'its links go, and also asks you to act.</font>')));

  // --- Technical details (collapsed): precise evidence for IT staff / the curious
  if (signals.length) {
    var technical = CardService.newCardSection()
      .setHeader('🛠️ Technical details')
      .setCollapsible(true)
      .setNumUncollapsibleWidgets(0);
    signals.forEach(function (signal) {
      technical.addWidget(CardService.newTextParagraph().setText(
        '<font color="' + GREY + '">' + escapeHtml_(signal.id) + ' · +' + Number(signal.points) +
        ' · ' + escapeHtml_(signal.strength) + '</font><br>' +
        isolate_(escapeHtml_(signal.technical || signal.detail))));
    });
    card.addSection(technical);
  }

  return card.build();
}

/** Full-width logo at the top of every card. */
function logoSection_() {
  return CardService.newCardSection()
    .addWidget(CardService.newImage().setImageUrl(LOGO_URL).setAltText(APP_NAME + ' logo'));
}

/** Section title in bold (Gmail's built-in section headers can't be bold). */
function heading_(text) {
  return CardService.newTextParagraph().setText('<b>' + text + '</b>');
}

function repeat_(text, times) {
  return new Array(Math.max(0, times) + 1).join(text);
}

function simpleCard_(text) {
  return CardService.newCardBuilder()
    .addSection(logoSection_())
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText(
        '🛡️ ' + isolate_(escapeHtml_(text)))))
    .build();
}

/**
 * Card text supports a small subset of HTML, so an attacker could put
 * tags in the subject or sender name to change what the card shows.
 * Escaping makes the text display literally.
 */
function escapeHtml_(text) {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Gmail shows the card right-to-left when its language is Hebrew.
 * Unicode "first strong isolate" marks let each piece of text pick its own
 * direction, so English stays LTR and Hebrew stays RTL.
 */
function isolate_(text) {
  return '⁨' + text + '⁩';
}
