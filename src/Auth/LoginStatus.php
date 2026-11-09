<?php

declare(strict_types=1);

namespace SecureAuth\Auth;

enum LoginStatus
{
    case Success;
    case InvalidCredentials;
    case EmailNotVerified;
    case Throttled;
}
