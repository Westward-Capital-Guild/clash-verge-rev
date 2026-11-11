import { createBrowserRouter, RouteObject } from 'react-router'

import Layout from './_layout'
import { navItems } from './_navigation'
import WorkspacePage from './workspace'

export const router = createBrowserRouter([
  {
    path: '/',
    Component: Layout,
    children: [
      { path: '/', Component: WorkspacePage },
      { path: '/development', Component: WorkspacePage },
      { path: '/workspace-settings', Component: WorkspacePage },
      ...navItems.map(
        (item) =>
          ({
            path: item.path === '/' ? '/network' : item.path,
            Component: item.Component,
          }) as RouteObject,
      ),
    ],
  },
])
