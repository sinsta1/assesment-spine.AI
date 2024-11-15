import {ApplicationConfig, provideZoneChangeDetection} from '@angular/core';
import {provideRouter} from '@angular/router';
import {routes} from './app.routes';
import {HTTP_INTERCEPTORS, provideHttpClient, withInterceptorsFromDi} from "@angular/common/http";
import {ReactiveFormsModule} from '@angular/forms';
import {provideAnimationsAsync} from '@angular/platform-browser/animations/async';
import {AuthInterceptor} from "./auth-interceptor.service";

export const appConfig: ApplicationConfig = {
  providers: [
    provideZoneChangeDetection({eventCoalescing: true}),
    provideRouter(routes),
    provideHttpClient(withInterceptorsFromDi()), provideAnimationsAsync(),
    ReactiveFormsModule,
    {provide: HTTP_INTERCEPTORS, useClass: AuthInterceptor, multi:true}
  ]
};