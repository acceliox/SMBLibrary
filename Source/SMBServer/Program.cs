/* Copyright (C) 2014 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Threading;
using System.Windows.Forms;

namespace SMBServer
{
    internal static class Program
    {
        public static void Application_ThreadException(object sender, ThreadExceptionEventArgs e)
        {
            HandleUnhandledException(e.Exception);
        }

        private static void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            if (e.ExceptionObject != null)
            {
                Exception ex = (Exception)e.ExceptionObject;
                HandleUnhandledException(ex);
            }
        }

        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        private static void Main()
        {
            Application.ThreadException += Application_ThreadException;
            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new ServerUI());
        }

        private static void HandleUnhandledException(Exception ex)
        {
            string message = string.Format("Exception: {0}: {1} Source: {2} {3}", ex.GetType(), ex.Message, ex.Source, ex.StackTrace);
            MessageBox.Show(message, "Error");
            Application.Exit();
        }
    }
}