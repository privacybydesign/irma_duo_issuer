'use strict';

var API = '/api/';

function init() {
    $('#btn-disclosure')
        .on('click', requestAttributes)
        .prop('disabled', false);
    $('#input-pdf')
        .on('change', updateIssueButton);
    $('#btn-issue')
        .on('click', startIssue);
}

function updateIssueButton(e) {
    console.log([$(e.target).val(), e.target.files[0]]);
}

function requestAttributes() {
    console.log('requesting attributes...');
    $.ajax({
        url: API + 'request-attrs',
    }).done(function(jwt) {
        console.log('JWT:', jwt);
        IRMA.verify(jwt,
            function(disclosureJWT) { // success
                console.log('disclosure JWT:', disclosureJWT);
            }, function() { // cancel
                console.warn('cancelled!');
            }, function(errormsg) {
                console.error('error during disclosure:', errormsg);
            });
    }).fail(function(data) {
        console.error('cannot get JWT:', data);
    });
}

function startIssue() {
    var fd = new FormData();
    fd.append('pdf', $('#input-pdf').prop('files')[0]);
    $.ajax({
        url: API + 'issue',
        method: 'POST',
        data: fd,
        processData: false,
        contentType: false,
    }).done(function() {
        console.log('upload success');
    }).fail(function() {
        console.warn('upload fail');
    });
}

init();
