package com.unipass.identity;

/** Only identity attributes. Passwords are never part of HR input. */
public record HrRow(
    String employeeNo, String directoryId, String displayName, String status, long sourceVersion) {}
