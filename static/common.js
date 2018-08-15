'use strict';

var API = '/api/';

var disclosureJWT;

function init() {
    $('#btn-disclosure')
        .on('click', requestAttributes)
        .prop('disabled', false);
    $('#input-pdf')
        .on('change', updateButtons);
    $('#btn-issue')
        .on('click', startIssue);
}

function updateButtons(e) {
    var hasPDF = $('#input-pdf').val();
    var hasName = disclosureJWT;
    if (hasPDF && hasName) {
        $('#btn-issue').prop('disabled', false);
    } else {
        $('#btn-issue').prop('disabled', true);
    }
    if (hasPDF) {
        $('#btn-pdf + .checkmark').addClass('visible');
    } else {
        $('#btn-pdf + .checkmark').removeClass('visible');
    }
    if (hasName) {
        $('#btn-disclosure + .checkmark').addClass('visible');
    } else {
        $('#btn-disclosure + .checkmark').removeClass('visible');
    }
}

function requestAttributes() {
    console.log('requesting attributes...');
    $.ajax({
        url: API + 'request-attrs',
    }).done(function(jwt) {
        console.log('JWT:', jwt);
        IRMA.verify(jwt,
            function(jwt2) { // success
                console.log('disclosure JWT:', jwt2);
                disclosureJWT = jwt2;
                updateButtons();
            }, function() { // cancel
                console.warn('cancelled!');
            }, function(errormsg) {
                console.error('error during disclosure:', errormsg);
            });
    }).fail(function(data) {
        console.error('cannot get JWT:', data);
    });
}

function startIssue(e) {
    e.target.disabled = true;
    var fd = new FormData();
    fd.append('pdf', $('#input-pdf').prop('files')[0]);
    fd.append('attributes', disclosureJWT);
    setStatus('info', MESSAGES['uploading']);
    $.ajax({
        url: API + 'issue',
        method: 'POST',
        data: fd,
        processData: false,
        contentType: false,
    }).done(function(jwt) {
        setStatus('info', MESSAGES['issuing']);
        IRMA.issue(jwt,
            function() { // success
                setStatus('success', MESSAGES['finished']);
                e.target.disabled = false;
            }, function() { // cancel
                setStatus('cancel');
                e.target.disabled = false;
            }, function(errormsg) {
                setStatus('danger', MESSAGES['issue-error'], errormsg);
                e.target.disabled = false;
            });
    }).fail(function(xhr) {
        e.target.disabled = false;
        console.error(xhr, xhr.responseText);
        setStatus('danger', MESSAGES['upload-error'], MESSAGES[xhr.responseText]);
        if (xhr.responseText == 'error:attributes-expired') {
            disclosureJWT = undefined;
            updateButtons();
        }
    });
}

// Show progress in the alert box.
function setStatus(alertType, message, errormsg) {
    console.log('user message: ' + alertType + ': ' + message);
    message = message || '???'; // make sure it's not undefined
    if (errormsg && errormsg.statusText) { // is this an XMLHttpRequest?
        errormsg = errormsg.status + ' ' + errormsg.statusText;
    }

    var alert = $('#result-alert')
    alert.removeClass('alert-success'); // remove all 4 alert types
    alert.removeClass('alert-info');
    alert.removeClass('alert-warning');
    alert.removeClass('alert-danger');
    alert.addClass('alert-' + alertType);
    alert.text(message);
    alert.removeClass('hidden');
    if (errormsg) {
        alert.append('<br>');
        alert.append($('<small></small>').text(errormsg));
    }
}

init();
